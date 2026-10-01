#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#include <ctype.h>
#include <stddef.h>

// ---- rsignal codes (include/rsignal.h) ---- 
#define RSIG_BOOTENGINE        0x4036
#define RSIG_SCAN_STREAMBUFFER 0x403D
#define RSIG_UNLOADENGINE      0x400A

// ---- engineboot.h ----
#define BOOT_ATTR_NORMAL          (1 << 0)
#define BOOT_ENABLELOGGING        (1 << 12)
#define ENGINE_UNPACK             (1 << 1)

typedef struct _ENGINE_INFO {
    DWORD field_0, field_4, field_8, field_C;
    BYTE  ModernTail[0x400];
} ENGINE_INFO;

typedef struct _ENGINE_CONFIG {
    DWORD  EngineFlags;
    PWCHAR Inclusions;
    PVOID  Exceptions;
    PWCHAR UnknownString2;
    PWCHAR QuarantineLocation;
    DWORD  field_14, field_18, field_1C, field_20, field_24;
    DWORD  field_28, field_2C, field_30, field_34;
    PCHAR  UnknownAnsiString1;
    PCHAR  UnknownAnsiString2;
    // Modern engine reads at least +0x60; the old x86 layout stops here.
    BYTE   ModernTail[0x400];
} ENGINE_CONFIG;

typedef struct _ENGINE_CONTEXT {
    DWORD field_0;
} ENGINE_CONTEXT;

typedef struct _BOOTENGINE_PARAMS {
    DWORD            ClientVersion;
    PWCHAR           SignatureLocation;
    PVOID            SpynetSource;
    ENGINE_CONFIG   *EngineConfig;
    ENGINE_INFO     *EngineInfo;
    PWCHAR           ScanReportLocation;
    DWORD            BootFlags;
    PWCHAR           LocalCopyDirectory;
    PWCHAR           OfflineTargetOS;
    CHAR             ProductString[16];
    DWORD            field_34;
    PVOID            GlobalCallback;
    ENGINE_CONTEXT  *EngineContext;
    DWORD            AvgCpuLoadFactor;
    CHAR             field_44[16];
    PWCHAR           SpynetReportingGUID;
    PWCHAR           SpynetVersion;
    PWCHAR           NISEngineVersion;
    PWCHAR           NISSignatureVersion;
    DWORD            FlightingEnabled;
    DWORD            FlightingLevel;
    PVOID            DynamicConfig;
    DWORD            AutoSampleSubmission;
    DWORD            EnableThreatLogging;
    PWCHAR           ProductName;
    DWORD            PassiveMode;
    DWORD            SenseEnabled;
    PWCHAR           SenseOrgId;
    DWORD            Attributes;
    DWORD            BlockAtFirstSeen;
    DWORD            PUAProtection;
    DWORD            SideBySidePassiveMode;
} BOOTENGINE_PARAMS;

// ---- scanreply.h ---- 
#define SCAN_VIRUSFOUND (1 << 27)

typedef struct _SCANSTRUCT {
    DWORD field_0;
    DWORD Flags;
    PCHAR FileName;
    CHAR  VirusName[28];
    BYTE  tail[256];
} SCANSTRUCT;

typedef struct _SCAN_REPLY {
    DWORD (*EngineScanCallback)(SCANSTRUCT *self);
    DWORD field_8;
    PVOID UserPtr;
    DWORD field_18;
} SCAN_REPLY;

// ---- streambuffer.h ----
typedef struct _STREAMBUFFER_DESCRIPTOR {
    PVOID  UserPtr;
    DWORD  (*Read)(PVOID self, uint64_t Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead);
    DWORD  (*Write)(PVOID self, uint64_t Offset, PVOID Buffer, DWORD Size, PDWORD TotalWritten);
    DWORD  (*GetSize)(PVOID self, uint64_t *FileSize);
    DWORD  (*SetSize)(PVOID self, uint64_t *FileSize);
    PWCHAR (*GetName)(PVOID self);
    DWORD  (*SetAttributes)(PVOID self, DWORD Attribute, PVOID Data, DWORD DataSize);
    DWORD  (*GetAttributes)(PVOID self, DWORD Attribute, PVOID Data, DWORD DataSize, PDWORD Written);
} STREAMBUFFER_DESCRIPTOR;

typedef struct _SCANSTREAM_PARAMS {
    STREAMBUFFER_DESCRIPTOR *Descriptor;
    SCAN_REPLY              *ScanReply;
    DWORD                    UnknownB;
    DWORD                    UnknownC;
    uint64_t                 ModernReserved;
} SCANSTREAM_PARAMS;

typedef int (*RSIGNAL)(PVOID *KernelHandle, DWORD Code, PVOID Params, SIZE_T Size);


static PVOID  KernelHandle;
static int    DetectionCount;
static int    CallbackCount;
static int    ReadCount;
static uint64_t ReadBytes;
static int    EicarNamedCount;
static BYTE  *EngineBase;
static size_t EngineSize;

#define BOOT_PARAMS_MODERN 0xA900
#define BOOT_PARAMS_SIZE   0x1E4

_Static_assert(offsetof(BOOTENGINE_PARAMS, SignatureLocation) == 0x08, "signature offset");
_Static_assert(offsetof(BOOTENGINE_PARAMS, EngineConfig) == 0x18, "config offset");
_Static_assert(offsetof(BOOTENGINE_PARAMS, EngineInfo) == 0x20, "info offset");
_Static_assert(offsetof(BOOTENGINE_PARAMS, Attributes) < BOOT_PARAMS_SIZE, "attributes offset");
_Static_assert(offsetof(ENGINE_CONFIG, ModernTail) == 0x60, "config tail offset");
_Static_assert(offsetof(SCAN_REPLY, field_18) == 0x18, "scan reply offset");
_Static_assert(sizeof(SCANSTREAM_PARAMS) == 0x20, "modern scan request size");

static void  *BootParamsAddr;
static size_t BootParamsSize;

static struct {
    BYTE  *Data;
    DWORD  Size;
    WCHAR  Name[MAX_PATH];
} Target;

static DWORD ReadStream(PVOID self, uint64_t Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    (void)self;
    ReadCount++;
    if (Offset >= Target.Size) {
        *SizeRead = 0;
        return TRUE;
    }
    DWORD avail = Target.Size - (DWORD)Offset;
    if (Size > avail)
        Size = avail;
    memcpy(Buffer, Target.Data + Offset, Size);
    *SizeRead = Size;
    ReadBytes += Size;
    return TRUE;
}

static DWORD GetStreamSize(PVOID self, uint64_t *FileSize)
{
    (void)self;
    *FileSize = Target.Size;
    return TRUE;
}

static PWCHAR GetStreamName(PVOID self)
{
    (void)self;
    return Target.Name;
}

static DWORD WriteStream(PVOID self, uint64_t Offset, PVOID Buffer, DWORD Size, PDWORD Written)
{
    (void)self; (void)Offset; (void)Buffer; (void)Size;
    *Written = 0;
    return FALSE;
}

static DWORD SetStreamSize(PVOID self, uint64_t *FileSize)
{
    (void)self; (void)FileSize;
    return FALSE;
}

static DWORD SetStreamAttributes(PVOID self, DWORD Attribute, PVOID Data, DWORD DataSize)
{
    (void)self; (void)Attribute; (void)Data; (void)DataSize;
    return TRUE;
}

static DWORD GetStreamAttributes(PVOID self, DWORD Attribute, PVOID Data, DWORD DataSize, PDWORD Written)
{
    (void)self; (void)Attribute; (void)Data; (void)DataSize;
    if (Written)
        *Written = 0;
    return FALSE;
}

static void hexdump(const char *label, const void *p, size_t n)
{
    const BYTE *b = p;
    fprintf(stderr, "[mpscan] %s (%zu bytes):\n", label, n);
    for (size_t i = 0; i < n; i += 16) {
        fprintf(stderr, "  %04zx  ", i);
        for (size_t j = 0; j < 16; j++)
            fprintf(stderr, i + j < n ? "%02x " : "   ", b[i + j]);
        fprintf(stderr, " |");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            BYTE c = b[i + j];
            fputc(c >= 0x20 && c < 0x7f ? c : '.', stderr);
        }
        fprintf(stderr, "|\n");
    }
}

static LONG CALLBACK FaultHandler(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    BYTE *rip = (BYTE *)er->ExceptionAddress;
    static const char *access[] = { "read", "write", "execute" };
    ULONG_PTR kind = er->ExceptionInformation[0];
    ULONG_PTR addr = er->ExceptionInformation[1];

    fprintf(stderr, "\n[mpscan] ==== ACCESS VIOLATION ====\n");
    fprintf(stderr, "[mpscan] %s of %p at rip=%p\n", kind < 3 ? access[kind] : "?", (void *)addr, (void *)rip);
    if (EngineBase)
        fprintf(stderr, "[mpscan] mpengine base=%p  rip RVA=+%#llx\n", (void *)EngineBase, (unsigned long long)(rip - EngineBase));
    fprintf(stderr, "[mpscan] BootParams at %p size=%zu\n", BootParamsAddr, BootParamsSize);
    fprintf(stderr, "[mpscan] rax=%016llx rcx=%016llx rdx=%016llx\n",(unsigned long long)ep->ContextRecord->Rax, (unsigned long long)ep->ContextRecord->Rcx, (unsigned long long)ep->ContextRecord->Rdx);
    fprintf(stderr, "[mpscan] r8 =%016llx r9 =%016llx rbx=%016llx\n", (unsigned long long)ep->ContextRecord->R8, (unsigned long long)ep->ContextRecord->R9, (unsigned long long)ep->ContextRecord->Rbx);

    hexdump("code at rip-32", rip - 32, 64);

    fprintf(stderr, "[mpscan] stack return addresses into mpengine (rsp=%p):\n", (void *)ep->ContextRecord->Rsp);
    ULONG_PTR *sp = (ULONG_PTR *)ep->ContextRecord->Rsp;
    for (int i = 0; i < 128; i++) {
        ULONG_PTR v = sp[i];
        if (v >= (ULONG_PTR)EngineBase && v < (ULONG_PTR)EngineBase + EngineSize)
            fprintf(stderr, "[mpscan]   rsp+%#04x -> mpengine+%#llx\n", i * 8, (unsigned long long)(v - (ULONG_PTR)EngineBase));
    }

    if (BootParamsAddr)
        hexdump("BootParams", BootParamsAddr, BootParamsSize);

    fflush(stderr);
    ExitProcess(9);
}

static DWORD EngineScanCallback(SCANSTRUCT *scan)
{
    CallbackCount++;
    if (CallbackCount <= 8)
        fprintf(stderr, "[mpscan] callback %d flags=%#lx\n", CallbackCount, (unsigned long)scan->Flags);
    if (scan->Flags & SCAN_VIRUSFOUND) {
        DetectionCount++;
        char name[sizeof(scan->VirusName) + 1];
        memcpy(name, scan->VirusName, sizeof(scan->VirusName));
        name[sizeof(scan->VirusName)] = '\0';
        fprintf(stderr, "[mpscan] detection candidate: name=\"%s\" flags=%#lx\n", name, (unsigned long)scan->Flags);
        for (size_t i = 0; i < sizeof(scan->VirusName); i++) name[i] = (char)toupper((unsigned char)name[i]);
        if (strstr(name, "EICAR"))
            EicarNamedCount++;
        if (DetectionCount == 1)
            hexdump("SCANSTRUCT", scan, sizeof(SCANSTRUCT) - sizeof(((SCANSTRUCT *)0)->tail) + 96);
    }
    return 0;
}

static int load_target(const wchar_t *path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[mpscan] cannot open target (err=%lu)\n", GetLastError());
        return 0;
    }
    DWORD size = GetFileSize(h, NULL);
    Target.Data = malloc(size ? size : 1);
    if (!Target.Data || !ReadFile(h, Target.Data, size, &Target.Size, NULL)) {
        fprintf(stderr, "[mpscan] read failed (err=%lu)\n", GetLastError());
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);
    wcsncpy(Target.Name, path, MAX_PATH - 1);
    return 1;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: mpscan.exe <file-to-scan> [engine-dir]\n");
        return 2;
    }

    wchar_t engine_dir[MAX_PATH];
    if (argc >= 3) {
        wcsncpy(engine_dir, argv[2], MAX_PATH - 1);
    } else if (GetEnvironmentVariableW(L"MPSCAN_ENGINE_DIR", engine_dir, MAX_PATH) == 0) {
        GetModuleFileNameW(NULL, engine_dir, MAX_PATH);
        wchar_t *slash = wcsrchr(engine_dir, L'\\');
        if (slash)
            *slash = L'\0';
    }

    wchar_t engine_dll[MAX_PATH];
    swprintf(engine_dll, MAX_PATH, L"%ls\\mpengine.dll", engine_dir);

    fprintf(stderr, "[mpscan] engine dir : %ls\n", engine_dir);

    SetDllDirectoryW(engine_dir);
    SetCurrentDirectoryW(engine_dir);

    AddVectoredExceptionHandler(1, FaultHandler);

    HMODULE engine = LoadLibraryW(engine_dll);
    if (!engine) {
        fprintf(stderr, "[mpscan] LoadLibraryW(%ls) failed (err=%lu)\n", engine_dll, GetLastError());
        return 3;
    }

    RSIGNAL rsignal = (RSIGNAL)(void *)GetProcAddress(engine, "__rsignal");
    if (!rsignal) {
        fprintf(stderr, "[mpscan] mpengine.dll has no __rsignal export\n");
        return 3;
    }
    EngineBase = (BYTE *)engine;
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)EngineBase;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(EngineBase + dos->e_lfanew);
        EngineSize = nt->OptionalHeader.SizeOfImage;
    }
    fprintf(stderr, "[mpscan] mpengine loaded at %p, __rsignal at %p (RVA +%#llx)\n", (void *)engine, (void *)rsignal,(unsigned long long)((BYTE *)rsignal - EngineBase));

    ENGINE_CONFIG config = {0};
    ENGINE_INFO info = {0};
    config.EngineFlags = ENGINE_UNPACK;
    config.Inclusions = L"*.*";
    config.QuarantineLocation = L"C:\\defender\\Support";

    static BYTE params[BOOT_PARAMS_SIZE + 16];
    *(DWORD *)(params + 0x00) = BOOT_PARAMS_MODERN;
    *(wchar_t **)(params + 0x08) = engine_dir;
    *(ENGINE_CONFIG **)(params + 0x18) = &config;
    *(ENGINE_INFO **)(params + 0x20) = &info;
    *(DWORD *)(params + offsetof(BOOTENGINE_PARAMS, Attributes)) = BOOT_ATTR_NORMAL;

    BootParamsAddr = params;
    BootParamsSize = BOOT_PARAMS_SIZE;
    fprintf(stderr, "[mpscan] BOOTENGINE: version=%#x size=%d config=%p info=%p\n", BOOT_PARAMS_MODERN, BOOT_PARAMS_SIZE, (void *)&config, (void *)&info);

    int rc = rsignal(&KernelHandle, RSIG_BOOTENGINE, params, BOOT_PARAMS_SIZE);
    if (rc != 0) {
        fprintf(stderr, "[mpscan] RSIG_BOOTENGINE failed rc=%#x\n", rc);
        return 4;
    }
    fprintf(stderr, "[mpscan] engine booted. handle=%p\n", KernelHandle);
    if (!KernelHandle) {
        fprintf(stderr, "[mpscan] BOOTENGINE returned success without an engine handle\n");
        return 4;
    }

    if (!load_target(argv[1]))
        return 5;
    fprintf(stderr, "[mpscan] scanning %ls (%lu bytes)\n", Target.Name, (unsigned long)Target.Size);

    STREAMBUFFER_DESCRIPTOR desc = {0};
    desc.UserPtr       = &Target;
    desc.Read          = ReadStream;
    desc.Write         = WriteStream;
    desc.GetSize       = GetStreamSize;
    desc.SetSize       = SetStreamSize;
    desc.GetName       = GetStreamName;
    desc.SetAttributes = SetStreamAttributes;
    desc.GetAttributes = GetStreamAttributes;

    SCAN_REPLY reply = {0};
    reply.EngineScanCallback = EngineScanCallback;
    reply.field_18 = 0x7fffffff;

    SCANSTREAM_PARAMS scan = {0};
    scan.Descriptor = &desc;
    scan.ScanReply  = &reply;

    rc = rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &scan, sizeof scan);
    if (rc != 0) {
        fprintf(stderr, "[mpscan] RSIG_SCAN_STREAMBUFFER failed rc=%#x reads=%d callbacks=%d\n", rc, ReadCount, CallbackCount);
        return 6;
    }

    fprintf(stderr, "[mpscan] scan summary: reads=%d bytes=%llu callbacks=%d candidates=%d eicar_names=%d\n", ReadCount, (unsigned long long)ReadBytes, CallbackCount, DetectionCount, EicarNamedCount);
    rsignal(&KernelHandle, RSIG_UNLOADENGINE, NULL, 0);
    if (!ReadBytes) {
        fprintf(stderr, "[mpscan] UNVERIFIED: engine received no sample bytes\n");
        return 7;
    }
    if (GetEnvironmentVariableA("MPSCAN_EXPECT_EICAR", NULL, 0) > 0) {
        if (EicarNamedCount > 0 && DetectionCount > 0) {
            fprintf(stderr, "[mpscan] EICAR_CONFIRMED: name and detection flag observed\n");
            return 1;
        }
        fprintf(stderr, "[mpscan] UNVERIFIED: EICAR detection was not confirmed\n");
        return 7;
    }
    if (DetectionCount > 0) {
        fprintf(stderr, "[mpscan] DETECTION_REPORTED: engine raised a detection callback\n");
        return 1;
    }
    fprintf(stderr, "[mpscan] UNVERIFIED: no detection reported; a clean verdict is not established\n");
    return 7;
}

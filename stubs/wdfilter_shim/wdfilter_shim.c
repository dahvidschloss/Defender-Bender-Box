#include <windows.h>
#include <winternl.h>
#include <rpc.h>
#include <rpcdce.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "iat_hook.h"

// forward decl called from hooked_LoadLibraryExW
static void install_hooks(void);  

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef FILE_OPENED
#define FILE_OPENED 0x00000001L
#endif

// Define function singuaturse for low-level NT and Win32 APIs we want to hook or call
typedef NTSTATUS (NTAPI *pNtCreateFile_t)( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtDeviceIoControlFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtClose_t)(HANDLE);
typedef HMODULE (WINAPI *pLoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef FARPROC (WINAPI *pGetProcAddress_t)(HMODULE, LPCSTR);
typedef LSTATUS (APIENTRY *pRegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (APIENTRY *pRegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (APIENTRY *pRegGetValueW_t)( HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);

// Storage variables for the original function address so we can call them just incase they are needed
static pNtCreateFile_t      orig_NtCreateFile;
static pNtDeviceIoControlFile_t orig_NtDeviceIoControlFile;
static pNtClose_t               orig_NtClose;
static pLoadLibraryExW_t    orig_LoadLibraryExW;
static pGetProcAddress_t    orig_GetProcAddress;
static pRegOpenKeyExW_t     orig_RegOpenKeyExW;
static pRegQueryValueExW_t  orig_RegQueryValueExW;
static pRegGetValueW_t      orig_RegGetValueW;

// Single env-var gate for all shim logging (WDSHIM_LOG=1).
static int g_log_on = -1;
static int log_on(void)
{
    if (g_log_on < 0) {
        char b[8];
        DWORD n = GetEnvironmentVariableA("WDSHIM_LOG", b, sizeof(b));
        g_log_on = (n > 0 && b[0] == '1') ? 1 : 0;
    }
    return g_log_on;
}

// More signatures for File and IO control ops
typedef HANDLE (WINAPI *pCreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *pCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *pDeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

static pCreateFileW_t      orig_CreateFileW;
static pCreateFileA_t      orig_CreateFileA;
static pDeviceIoControl_t  orig_DeviceIoControl;

// Create "fake" handles started at our magic constant 0xDEFFEAD00 to reresent the Defender driver. 
#define FAKE_HANDLE_BASE  ((HANDLE)(uintptr_t)0xDEFEAD00)
// Thread-safe counter for the unique IDs
static volatile LONG g_fake_counter = 0;

// this func checks if a file path is trying to access a Windows Def device driver (in UNICODE)
static int is_wd_device_w(LPCWSTR p) 
{
    if (!p) return 0;

    static const wchar_t *prefixes[] = {L"\\\\.\\Wd", L"\\\\?\\Wd", L"\\??\\Wd", L"\\Device\\Wd", NULL};
    for (int i = 0; prefixes[i]; i++) 
    {
        size_t n = wcslen(prefixes[i]);
        if (_wcsnicmp(p, prefixes[i], n) == 0) return 1;
    }
    return 0;
}


// This func is the same as above but instead of "wide" characters its for ASCII. Gotta cover all bases
static int is_wd_device_a(LPCSTR p) 
{
    if (!p) return 0;
    static const char *prefixes[] = {"\\\\.\\Wd", "\\\\?\\Wd", "\\??\\Wd", "\\Device\\Wd", NULL};
    for (int i = 0; prefixes[i]; i++) 
    {
        size_t n = strlen(prefixes[i]);
        if (_strnicmp(p, prefixes[i], n) == 0) return 1;
    }
    return 0;
}


// This function is a "fake boolean" to check if the handle provided was one we created outselves
static int is_fake_handle(HANDLE h) 
{
    uintptr_t v = (uintptr_t)h;
    return (v >= (uintptr_t)FAKE_HANDLE_BASE) && (v <  (uintptr_t)FAKE_HANDLE_BASE + 0x10000);
}

// This fucntion is what generates unique fake handle values for shimming
static HANDLE mint_fake_handle(void) 
{
    LONG n = InterlockedIncrement(&g_fake_counter);
    return (HANDLE)((uintptr_t)FAKE_HANDLE_BASE + (uintptr_t)n);
}

// This function is for logging. prints to STDERR if WDSHIM_LOG is = 1
static void shim_log(const char *fmt, ...)
{
    if (!log_on()) return;
    va_list ap;
    va_start(ap, fmt);
    char line[512];
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[wdshim] %s\n", line);
}

// Catch WdFilter/WdNisDrv driver-file opens via absolute path (\??\C:\windows\system32\drivers\Wd*)
static int is_wd_driver_path_w(LPCWSTR p)
{
    if (!p) return 0;
    static const wchar_t needle[] = L"\\drivers\\Wd";
    size_t nlen = (sizeof(needle) / sizeof(wchar_t)) - 1;
    for (const wchar_t *c = p; *c; c++) {
        if (_wcsnicmp(c, needle, nlen) == 0) return 1;
    }
    return 0;
}


// ---------- Replacements ----------

//T This function intercepts file creation. If Defender asks for its driver, we give it a fake handle instead
static HANDLE WINAPI hooked_CreateFileW(LPCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE templ)
{
    if (is_wd_device_w(path)) 
    {
        shim_log("CreateFileW(WdDevice) -> fake handle");
        SetLastError(ERROR_SUCCESS);
        return mint_fake_handle();
    }
    // if the above isn't true then log the path and call the real fucntion
    if (log_on() && path) 
    {
        char ascii[512];
        WideCharToMultiByte(CP_UTF8, 0, path, -1, ascii, sizeof(ascii), NULL, NULL);
        fprintf(stderr, "[wdshim] CreateFileW: %s\n", ascii);
        fflush(stderr);
    }
    HANDLE h = orig_CreateFileW(path, access, share, sa, disp, flags, templ);
    if (log_on() && h == INVALID_HANDLE_VALUE && path) 
    {
        char ascii[512];
        WideCharToMultiByte(CP_UTF8, 0, path, -1, ascii, sizeof(ascii), NULL, NULL);
        fprintf(stderr, "[wdshim] CreateFileW FAILED (err=%lu): %s\n", GetLastError(), ascii);
        fflush(stderr);
    }
    return h;
}

// Intercepts NT-level file creation calls to catch direct syscalls.
static NTSTATUS NTAPI hooked_NtCreateFile(PHANDLE handle, ACCESS_MASK access, POBJECT_ATTRIBUTES attr, PIO_STATUS_BLOCK iosb, PLARGE_INTEGER alloc, ULONG fattr, ULONG share, ULONG disp, ULONG opts, PVOID ea, ULONG ea_len)
{
    if (attr && attr->ObjectName && attr->ObjectName->Buffer && attr->ObjectName->Length > 0)
    {
        int wlen = attr->ObjectName->Length / 2;
        if (wlen > 500) wlen = 500;
        wchar_t w[512] = {0};
        wmemcpy(w, attr->ObjectName->Buffer, wlen);

        // Intercept Wd device and driver-file opens before Wine's VFS sees them
        if (is_wd_device_w(w) || is_wd_driver_path_w(w))
        {
            shim_log("NtCreateFile(WdDevice) -> fake handle");
            if (handle) *handle = mint_fake_handle();
            if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = FILE_OPENED; }
            return STATUS_SUCCESS;
        }

        if (log_on())
        {
            char ascii[512];
            WideCharToMultiByte(CP_UTF8, 0, w, -1, ascii, sizeof(ascii), NULL, NULL);
            fprintf(stderr, "[wdshim] NtCreateFile: %s\n", ascii);
            fflush(stderr);
        }
    }
    NTSTATUS s = orig_NtCreateFile(handle, access, attr, iosb, alloc, fattr, share, disp, opts, ea, ea_len);
    if (log_on() && !NT_SUCCESS(s) && attr && attr->ObjectName && attr->ObjectName->Buffer && attr->ObjectName->Length > 0)
    {
        int wlen = attr->ObjectName->Length / 2;
        if (wlen > 500) wlen = 500;
        wchar_t w[512] = {0};
        wmemcpy(w, attr->ObjectName->Buffer, wlen);
        char ascii[512];
        WideCharToMultiByte(CP_UTF8, 0, w, -1, ascii, sizeof(ascii), NULL, NULL);
        fprintf(stderr, "[wdshim] NtCreateFile FAILED (status=0x%08lx): %s\n", (unsigned long)s, ascii);
        fflush(stderr);
    }
    return s;
}

// This here be a helper to get readable names for registry keys within our log. Not sure it works well but hey it works
static const char *hkey_name(HKEY h) 
{
    if (h == HKEY_LOCAL_MACHINE)        return "HKLM";
    if (h == HKEY_CURRENT_USER)         return "HKCU";
    if (h == HKEY_CLASSES_ROOT)         return "HKCR";
    if (h == HKEY_USERS)                return "HKU";
    if (h == HKEY_CURRENT_CONFIG)       return "HKCC";
    return "HKEY";
}

// This checks to see if the registry path belongs to WinDef, ATP, or AMSI
static int is_defender_keypath(LPCWSTR sk) {
    if (!sk) return 0;
    static const wchar_t *needles[] = 
    {
        L"Microsoft\\Windows Defender",
        L"Microsoft\\Windows Advanced Threat Protection",
        L"Microsoft\\Cryptography",
        L"Microsoft\\AMSI",
        L"Policies\\Microsoft\\Windows Defender",
        NULL
    };
    for (int i = 0; needles[i]; i++) 
    {
        for (const wchar_t *p = sk; *p; p++) 
        {
            if (_wcsnicmp(p, needles[i], wcslen(needles[i])) == 0)
                return 1;
        }
    }
    return 0;
}

// This intercepts registry open actions. If it fails, likely because wine fucked it up, it retries with Read-Only perms to see if thats ok
static LSTATUS APIENTRY hooked_RegOpenKeyExW(HKEY hkey, LPCWSTR subkey, DWORD opts, REGSAM access, PHKEY result)
{
    LSTATUS s = orig_RegOpenKeyExW(hkey, subkey, opts, access, result);

    if (s != ERROR_SUCCESS && is_defender_keypath(subkey)) 
    {
        //if we failed then lower perms because Wine is being strict and not operating how Windwos does with HKLM
        REGSAM retry_access = KEY_READ | (access & (KEY_WOW64_64KEY | KEY_WOW64_32KEY));
        LSTATUS s2 = orig_RegOpenKeyExW(hkey, subkey, opts, retry_access, result);
        if (log_on()) 
        {
            char a[512];
            WideCharToMultiByte(CP_UTF8, 0, subkey, -1, a, sizeof(a), NULL, NULL);
            fprintf(stderr, "[wdshim] RegOpenKey RETRY: %s\\%s (orig_access=0x%lx -> " "KEY_READ, status=%ld -> %ld)\n", hkey_name(hkey), a, (unsigned long)access, s, s2);
            fflush(stderr);
        }
        s = s2;
    }

    if (log_on() && subkey) 
    {
        char a[512];
        WideCharToMultiByte(CP_UTF8, 0, subkey, -1, a, sizeof(a), NULL, NULL);
        if (s == ERROR_SUCCESS) 
        {
            fprintf(stderr, "[wdshim] RegOpenKey OK: %s\\%s\n", hkey_name(hkey), a);
        } 
        else 
        {
            fprintf(stderr, "[wdshim] RegOpenKey FAIL (%ld): %s\\%s\n", s, hkey_name(hkey), a);
        }
        fflush(stderr);
    }
    return s;
}

// This logs when a registry value query fails, which si really only usful for debugging but we need it cause this is uncharted territory 
static LSTATUS APIENTRY hooked_RegQueryValueExW(HKEY hkey, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD data_len)
{
    LSTATUS s = orig_RegQueryValueExW(hkey, name, reserved, type, data, data_len);
    if (log_on() && s != ERROR_SUCCESS) 
    {
        char a[256] = "(default)";
        if (name) WideCharToMultiByte(CP_UTF8, 0, name, -1, a, sizeof(a), NULL, NULL);
        fprintf(stderr, "[wdshim] RegQueryValue FAIL (%ld): hkey=%p name=%s\n", s, (void *)hkey, a);
        fflush(stderr);
    }
    return s;
}

// This is siimilar to the above log only hook but for the higher level RegGetValueW API 
static LSTATUS APIENTRY hooked_RegGetValueW(HKEY hkey, LPCWSTR subkey, LPCWSTR value, DWORD flags, LPDWORD type, PVOID data, LPDWORD data_len)
{
    LSTATUS s = orig_RegGetValueW(hkey, subkey, value, flags, type, data, data_len);
    if (log_on() && s != ERROR_SUCCESS) {
        char sk[256] = "(null)", v[256] = "(null)";
        if (subkey) WideCharToMultiByte(CP_UTF8, 0, subkey, -1, sk, sizeof(sk), NULL, NULL);
        if (value)  WideCharToMultiByte(CP_UTF8, 0, value, -1, v, sizeof(v), NULL, NULL);
        fprintf(stderr, "[wdshim] RegGetValue FAIL (%ld): %s\\%s -> %s\n", s, hkey_name(hkey), sk, v);
        fflush(stderr);
    }
    return s;
}

// ---------- Servbice Control Manager (SCM) bypass ----------


//Define the struct to pass data to our fake service thread. Should have called it Gaslighter 
typedef struct { LPSERVICE_MAIN_FUNCTIONW main_func; LPCWSTR name; } service_ctx_t;


// This function is what runs the thread that WinDef's ServiceMain, since the OS won't do it for us and we have to pretend its a real boy
static DWORD WINAPI service_thread_proc(LPVOID param) 
{
    service_ctx_t *ctx = (service_ctx_t *)param;
    LPWSTR argv[2];
    // ServiceMain expects argv[0] = service name. Cast away const. 
    argv[0] = (LPWSTR)ctx->name;
    argv[1] = NULL;
    fprintf(stderr, "[wdshim] invoking ServiceMain(%ls) directly\n", ctx->name);
    fflush(stderr);
    ctx -> main_func(1, argv);
    fprintf(stderr, "[wdshim] ServiceMain(%ls) returned\n", ctx->name);
    fflush(stderr);
    return 0;
}

// This is where we intercept the call when WinDef tries to register with the Windows Service Manager. But it doesn't exist hence the bypass
static BOOL WINAPI hooked_StartServiceCtrlDispatcherW( const SERVICE_TABLE_ENTRYW *table)
{
    if (!table || !table[0].lpServiceName || !table[0].lpServiceProc) 
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    fprintf(stderr, "[wdshim] StartServiceCtrlDispatcherW hooked: bypassing SCM, " "calling %ls in-process\n", table[0].lpServiceName);
    fflush(stderr);

    // Instead of telling Windows "I am a service"; this is where we spin up a local thread and run it manually. Cause Wine don't got services
    static service_ctx_t ctx; 
    ctx.main_func = table[0].lpServiceProc;
    ctx.name      = table[0].lpServiceName;

    HANDLE thread = CreateThread(NULL, 0, service_thread_proc, &ctx, 0, NULL);
    if (!thread) 
    {
        SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
    /* Wait until ServiceMain returns. */
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    // Real SCM doesn't return the moment ServiceMain returns, it keeps the dispatcher alive so worker threads spawned by ServiceMain (the actual RPC server, scan workers, etc.) can keep running. 
    //If we return here, main() unwinds and the process exits, killing every worker. Block forever instead; the container itself manages the MsMpEng process lifecycle via timeout in entrypoint.sh. 

    fprintf(stderr, "[wdshim] ServiceMain returned; blocking dispatcher to keep " "process alive for RPC workers\n");
    fflush(stderr);
    // WinDef expects the dispatcher to block forever, so we need to loop infinitely here
    while (1) Sleep(60000);
    return TRUE; 
}

// This is a sub for WinDef as it needs the register cals to "succeed " so we just return a fake success value
static SERVICE_STATUS_HANDLE WINAPI hooked_RegisterServiceCtrlHandlerW(LPCWSTR name, LPHANDLER_FUNCTION handler)
{
    (void)name; (void)handler;
    return (SERVICE_STATUS_HANDLE)(uintptr_t)0xDEFEAD0001;
}

//  this is the same as above but extended
static SERVICE_STATUS_HANDLE WINAPI hooked_RegisterServiceCtrlHandlerExW(LPCWSTR name, LPHANDLER_FUNCTION_EX handler, LPVOID ctx)
{
    (void)name; (void)handler; (void)ctx;
    return (SERVICE_STATUS_HANDLE)(uintptr_t)0xDEFEAD0002;
}

// Another success stub
static BOOL WINAPI hooked_SetServiceStatus(SERVICE_STATUS_HANDLE handle, LPSERVICE_STATUS status)
{
    (void)handle; (void)status;
    return TRUE;
}

// This function is logging when WinDef loads extra DLLS, mostly being used to see if MpClient.dll is loading correctly
static HMODULE WINAPI hooked_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    HMODULE r = orig_LoadLibraryExW(name, file, flags);
    if (log_on() && name) {
        char ascii[512];
        WideCharToMultiByte(CP_UTF8, 0, name, -1, ascii, sizeof(ascii),
                            NULL, NULL);
        if (r) {
            fprintf(stderr, "[wdshim] LoadLibrary: %s -> %p\n", ascii,
                    (void *)r);
        } else {
            fprintf(stderr, "[wdshim] LoadLibrary FAILED (err=%lu): %s\n",
                    GetLastError(), ascii);
        }
        fflush(stderr);
    }
    // Re-hook after every successful load so late-loaded DLLs (mpsvc.dll, // mpengine.dll, etc.) get their IATs patched with our intercepts. iat_hook_all is idempotent
    if (r) install_hooks();
    return r;
}

// This function is the ASCII version of the CreateFile hook
static HANDLE WINAPI hooked_CreateFileA(LPCSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE templ)
{
    if (is_wd_device_a(path)) {
        shim_log("CreateFileA(WdDevice) -> fake handle");
        SetLastError(ERROR_SUCCESS);
        return mint_fake_handle();
    }
    return orig_CreateFileA(path, access, share, sa, disp, flags, templ);
}

// This function is for intercepting IO Control codes. If they are sent to our fake handles, we just say "yes it worked"
static BOOL WINAPI hooked_DeviceIoControl(HANDLE h, DWORD ioctl, LPVOID in_buf, DWORD in_size, LPVOID out_buf, DWORD out_size, LPDWORD bytes_returned, LPOVERLAPPED ov)
{
    if (is_fake_handle(h)) 
    {
        shim_log("DeviceIoControl(fake, ioctl=0x%08lx, in=%lu, out=%lu)", ioctl, in_size, out_size);
        // Zero out the output buffer so callers don't read garbage.
        if (out_buf && out_size) memset(out_buf, 0, out_size);
        if (bytes_returned) *bytes_returned = out_size;
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }
    return orig_DeviceIoControl(h, ioctl, in_buf, in_size, out_buf, out_size, bytes_returned, ov);
}

// Intercept NT-level IOCTLs on fake handles (WdFilter, WdNisDrv driver IOCTLs)
static NTSTATUS NTAPI hooked_NtDeviceIoControlFile(HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, PVOID ctx, PIO_STATUS_BLOCK iosb, ULONG ioctl_code, PVOID in_buf, ULONG in_len, PVOID out_buf, ULONG out_len)
{
    if (is_fake_handle(file))
    {
        shim_log("NtDeviceIoControlFile(fake, ioctl=0x%08lx)", (unsigned long)ioctl_code);
        if (out_buf && out_len) memset(out_buf, 0, out_len);
        if (iosb) { iosb->Status = STATUS_SUCCESS; iosb->Information = 0; }
        return STATUS_SUCCESS;
    }
    return orig_NtDeviceIoControlFile(file, event, apc, ctx, iosb, ioctl_code, in_buf, in_len, out_buf, out_len);
}

// Prevent Wine from erroring on CloseHandle of our fake handles
static NTSTATUS NTAPI hooked_NtClose(HANDLE h)
{
    if (is_fake_handle(h)) return STATUS_SUCCESS;
    return orig_NtClose(h);
}

// ---------- RPC diagnostic hooks ----------
// Log-and-passthrough hooks for rpcrt4 functions to see if MsMpEng ever calls them.
// Excuse me but are are you actually reading the code? Da fuck is wrong with you

typedef RPC_STATUS (RPC_ENTRY *pRpcServerUseProtseqEpW_t)(RPC_WSTR, unsigned int, RPC_WSTR, void *);
typedef RPC_STATUS (RPC_ENTRY *pRpcServerRegisterIf2_t)(RPC_IF_HANDLE, UUID *, RPC_IF_CALLBACK_FN *, unsigned int, unsigned int, unsigned int, RPC_IF_CALLBACK_FN *);
typedef RPC_STATUS (RPC_ENTRY *pRpcServerListen_t)(unsigned int, unsigned int, unsigned int);

static pRpcServerUseProtseqEpW_t orig_RpcServerUseProtseqEpW;
static pRpcServerRegisterIf2_t   orig_RpcServerRegisterIf2;
static pRpcServerListen_t        orig_RpcServerListen;

static RPC_STATUS RPC_ENTRY hooked_RpcServerUseProtseqEpW(RPC_WSTR protseq, unsigned int max_calls, RPC_WSTR endpoint, void *sd)
{
    char ps[128] = {0}, ep[256] = {0};
    if (protseq) WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)protseq, -1, ps, sizeof(ps), NULL, NULL);
    if (endpoint) WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)endpoint, -1, ep, sizeof(ep), NULL, NULL);
    RPC_STATUS s = orig_RpcServerUseProtseqEpW(protseq, max_calls, endpoint, sd);
    fprintf(stderr, "[wdshim] RpcServerUseProtseqEpW(\"%s\", %u, \"%s\") -> %ld\n", ps, max_calls, ep, (long)s);
    fflush(stderr);
    return s;
}

static RPC_STATUS RPC_ENTRY hooked_RpcServerRegisterIf2(RPC_IF_HANDLE if_spec, UUID *mgr_type_uuid, RPC_IF_CALLBACK_FN *mgr_epv, unsigned int flags, unsigned int max_calls, unsigned int max_rpc_size, RPC_IF_CALLBACK_FN *cb)
{
    RPC_STATUS s = orig_RpcServerRegisterIf2(if_spec, mgr_type_uuid, (RPC_IF_CALLBACK_FN *)mgr_epv, flags, max_calls, max_rpc_size, cb);
    fprintf(stderr, "[wdshim] RpcServerRegisterIf2(flags=0x%x, max_calls=%u) -> %ld\n", flags, max_calls, (long)s);
    fflush(stderr);
    return s;
}

static RPC_STATUS RPC_ENTRY hooked_RpcServerListen(unsigned int min, unsigned int max_calls, unsigned int dont_wait)
{
    fprintf(stderr, "[wdshim] RpcServerListen(min=%u, max=%u, dont_wait=%u)\n", min, max_calls, dont_wait);
    fflush(stderr);
    RPC_STATUS s = orig_RpcServerListen(min, max_calls, dont_wait);
    fprintf(stderr, "[wdshim] RpcServerListen -> %ld\n", (long)s);
    fflush(stderr);
    return s;
}

// ---------- GetProcAddress hook ----------
// mpsvc.dll uses GetProcAddress to resolve rpcrt4 functions, bypassing IAT. Intercept and redirect to our logging wrappers.
static HMODULE g_rpcrt4_handle = NULL;

static FARPROC WINAPI hooked_GetProcAddress(HMODULE mod, LPCSTR name)
{
    // Only intercept rpcrt4 lookups
    if (mod && name && !IS_INTRESOURCE(name) && g_rpcrt4_handle && mod == g_rpcrt4_handle) {
        if (strcmp(name, "RpcServerUseProtseqEpW") == 0 && orig_RpcServerUseProtseqEpW) {
            shim_log("GetProcAddress(rpcrt4, RpcServerUseProtseqEpW) -> redirected");
            return (FARPROC)hooked_RpcServerUseProtseqEpW;
        }
        if (strcmp(name, "RpcServerRegisterIf2") == 0 && orig_RpcServerRegisterIf2) {
            shim_log("GetProcAddress(rpcrt4, RpcServerRegisterIf2) -> redirected");
            return (FARPROC)hooked_RpcServerRegisterIf2;
        }
        if (strcmp(name, "RpcServerListen") == 0 && orig_RpcServerListen) {
            shim_log("GetProcAddress(rpcrt4, RpcServerListen) -> redirected");
            return (FARPROC)hooked_RpcServerListen;
        }
    }
    return orig_GetProcAddress(mod, name);
}

// ---------- Entry ----------

//This be the main event. Its the "Installer". This will swap the real Windows functions for our "hooked" ones. 
static void install_hooks(void) 
{
    // We implement using IAT hooking to replace funcitons in kernel32, ntdll, and advapi32
    iat_hook_all("kernel32.dll", "GetProcAddress", (void *)hooked_GetProcAddress, (void **)&orig_GetProcAddress);
    iat_hook_all("kernel32.dll", "CreateFileW", (void *)hooked_CreateFileW, (void **)&orig_CreateFileW);
    iat_hook_all("kernel32.dll", "CreateFileA", (void *)hooked_CreateFileA, (void **)&orig_CreateFileA);
    iat_hook_all("kernel32.dll", "DeviceIoControl", (void *)hooked_DeviceIoControl, (void **)&orig_DeviceIoControl);
    iat_hook_all("kernel32.dll", "LoadLibraryExW", (void *)hooked_LoadLibraryExW, (void **)&orig_LoadLibraryExW);
    iat_hook_all("ntdll.dll", "NtCreateFile",  (void *)hooked_NtCreateFile, (void **)&orig_NtCreateFile);
    iat_hook_all("ntdll.dll", "NtDeviceIoControlFile", (void *)hooked_NtDeviceIoControlFile, (void **)&orig_NtDeviceIoControlFile);
    iat_hook_all("ntdll.dll", "NtClose", (void *)hooked_NtClose, (void **)&orig_NtClose);
    iat_hook_all("advapi32.dll", "RegOpenKeyExW", (void *)hooked_RegOpenKeyExW, (void **)&orig_RegOpenKeyExW);
    iat_hook_all("advapi32.dll", "RegQueryValueExW", (void *)hooked_RegQueryValueExW, (void **)&orig_RegQueryValueExW);
    iat_hook_all("advapi32.dll", "RegGetValueW", (void *)hooked_RegGetValueW, (void **)&orig_RegGetValueW);

    // SCM bypass
    iat_hook_all("advapi32.dll", "StartServiceCtrlDispatcherW", (void *)hooked_StartServiceCtrlDispatcherW, NULL);
    iat_hook_all("advapi32.dll", "RegisterServiceCtrlHandlerW", (void *)hooked_RegisterServiceCtrlHandlerW, NULL);
    iat_hook_all("advapi32.dll", "RegisterServiceCtrlHandlerExW", (void *)hooked_RegisterServiceCtrlHandlerExW, NULL);
    iat_hook_all("advapi32.dll", "SetServiceStatus", (void *)hooked_SetServiceStatus, NULL);
    
    // sechost.dll is where these live in modern Windows; advapi32 forwards.
    iat_hook_all("sechost.dll", "StartServiceCtrlDispatcherW", (void *)hooked_StartServiceCtrlDispatcherW, NULL);
    iat_hook_all("sechost.dll", "RegisterServiceCtrlHandlerW", (void *)hooked_RegisterServiceCtrlHandlerW, NULL);
    iat_hook_all("sechost.dll", "RegisterServiceCtrlHandlerExW", (void *)hooked_RegisterServiceCtrlHandlerExW, NULL);
    iat_hook_all("sechost.dll", "SetServiceStatus", (void *)hooked_SetServiceStatus, NULL);

    // RPC diagnostic hooks — log whether MsMpEng even calls these
    iat_hook_all("rpcrt4.dll", "RpcServerUseProtseqEpW", (void *)hooked_RpcServerUseProtseqEpW, (void **)&orig_RpcServerUseProtseqEpW);
    iat_hook_all("rpcrt4.dll", "RpcServerRegisterIf2", (void *)hooked_RpcServerRegisterIf2, (void **)&orig_RpcServerRegisterIf2);
    iat_hook_all("rpcrt4.dll", "RpcServerListen", (void *)hooked_RpcServerListen, (void **)&orig_RpcServerListen);

    // This section is a fallback. if IAT hooking failed, we can use GetProcAddress to find the original function manually
    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!orig_GetProcAddress)
        orig_GetProcAddress = (pGetProcAddress_t)(void *)GetProcAddress(k32, "GetProcAddress");
    if (!orig_CreateFileW)
        orig_CreateFileW = (pCreateFileW_t)(void *) GetProcAddress(k32, "CreateFileW");
    if (!orig_CreateFileA)
        orig_CreateFileA = (pCreateFileA_t)(void *) GetProcAddress(k32, "CreateFileA");
    if (!orig_DeviceIoControl)
        orig_DeviceIoControl = (pDeviceIoControl_t)(void *) GetProcAddress(k32, "DeviceIoControl");
    if (!orig_LoadLibraryExW)
        orig_LoadLibraryExW = (pLoadLibraryExW_t)(void *) GetProcAddress(k32, "LoadLibraryExW");
    if (!orig_NtCreateFile)
        orig_NtCreateFile = (pNtCreateFile_t)(void *) GetProcAddress(ntdll, "NtCreateFile");
    if (!orig_NtDeviceIoControlFile)
        orig_NtDeviceIoControlFile = (pNtDeviceIoControlFile_t)(void *)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (!orig_NtClose)
        orig_NtClose = (pNtClose_t)(void *)GetProcAddress(ntdll, "NtClose");
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    if (!adv) adv = LoadLibraryA("advapi32.dll");
    if (!orig_RegOpenKeyExW)
        orig_RegOpenKeyExW = (pRegOpenKeyExW_t)(void *) GetProcAddress(adv, "RegOpenKeyExW");
    if (!orig_RegQueryValueExW)
        orig_RegQueryValueExW = (pRegQueryValueExW_t)(void *) GetProcAddress(adv, "RegQueryValueExW");
    if (!orig_RegGetValueW)
        orig_RegGetValueW = (pRegGetValueW_t)(void *) GetProcAddress(adv, "RegGetValueW");
    HMODULE rpc = GetModuleHandleA("rpcrt4.dll");
    if (!rpc) rpc = LoadLibraryA("rpcrt4.dll");
    g_rpcrt4_handle = rpc;
    if (!orig_RpcServerUseProtseqEpW)
        orig_RpcServerUseProtseqEpW = (pRpcServerUseProtseqEpW_t)(void *)GetProcAddress(rpc, "RpcServerUseProtseqEpW");
    if (!orig_RpcServerRegisterIf2)
        orig_RpcServerRegisterIf2 = (pRpcServerRegisterIf2_t)(void *)GetProcAddress(rpc, "RpcServerRegisterIf2");
    if (!orig_RpcServerListen)
        orig_RpcServerListen = (pRpcServerListen_t)(void *)GetProcAddress(rpc, "RpcServerListen");
}

// This is a dummy export so the other tools can see 
__declspec(dllexport) void wdshim_loaded(void) { /* no-op */ }

// Entry point. 
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) 
    {
        //Optimization statment
        DisableThreadLibraryCalls(hinst);
        // Apply all the lies
        install_hooks();
        fprintf(stderr, "[wdshim] attached to pid %lu\n", GetCurrentProcessId());
        fflush(stderr);
    }
    return TRUE;
}

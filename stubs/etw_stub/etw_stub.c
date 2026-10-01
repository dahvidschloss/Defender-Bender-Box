#include <windows.h>
#include <evntprov.h>
#include <stdint.h>
#include <stdio.h>
#include "iat_hook.h"

typedef ULONG (WINAPI *pEventRegister_t)(LPCGUID, PENABLECALLBACK, PVOID, PREGHANDLE);
typedef ULONG (WINAPI *pEventUnregister_t)(REGHANDLE);
typedef ULONG (WINAPI *pEventWrite_t)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
typedef BOOLEAN (WINAPI *pEventEnabled_t)(REGHANDLE, PCEVENT_DESCRIPTOR);

static pEventRegister_t   orig_EventRegister;
static pEventUnregister_t orig_EventUnregister;
static pEventWrite_t      orig_EventWrite;
static pEventEnabled_t    orig_EventEnabled;

static volatile LONG g_reg_counter = 0;

static ULONG WINAPI stub_EventRegister(LPCGUID provider, PENABLECALLBACK cb, PVOID ctx, PREGHANDLE handle)
{
    (void)provider; (void)cb; (void)ctx;
    if (handle) *handle = (REGHANDLE)InterlockedIncrement(&g_reg_counter);
    return ERROR_SUCCESS;
}

static ULONG WINAPI stub_EventUnregister(REGHANDLE h) {
    (void)h;
    return ERROR_SUCCESS;
}

static ULONG WINAPI stub_EventWrite(REGHANDLE h, PCEVENT_DESCRIPTOR desc, ULONG count, PEVENT_DATA_DESCRIPTOR data)
{
    (void)h; (void)desc; (void)count; (void)data;
    return ERROR_SUCCESS;
}

// no consumers listening",  caller skips formatting work 
static BOOLEAN WINAPI stub_EventEnabled(REGHANDLE h, PCEVENT_DESCRIPTOR desc) {
    (void)h; (void)desc;
    return FALSE; 
}

static ULONG WINAPI stub_EventWriteEx(REGHANDLE h, PCEVENT_DESCRIPTOR d, ULONG64 filter, ULONG flags, LPCGUID act_id, LPCGUID rel_act_id, ULONG count, PEVENT_DATA_DESCRIPTOR data)
{
    (void)h; (void)d; (void)filter; (void)flags; (void)act_id; (void)rel_act_id; (void)count; (void)data;
    return ERROR_SUCCESS;
}

static ULONG WINAPI stub_EventWriteTransfer(REGHANDLE h, PCEVENT_DESCRIPTOR d, LPCGUID act_id, LPCGUID rel_act_id, ULONG count, PEVENT_DATA_DESCRIPTOR data)
{
    (void)h; (void)d; (void)act_id; (void)rel_act_id; (void)count; (void)data;
    return ERROR_SUCCESS;
}

static ULONG WINAPI stub_EventActivityIdControl(ULONG ctrl_code, LPGUID act_id)
{
    if (act_id) memset(act_id, 0, sizeof(GUID));
    (void)ctrl_code;
    return ERROR_SUCCESS;
}

static BOOLEAN WINAPI stub_EventProviderEnabled(REGHANDLE h, UCHAR level, ULONGLONG keyword)
{
    (void)h; (void)level; (void)keyword;
    return FALSE;
}

static void install(void) {
    // advapi32 is the canonical home; api-ms-win-eventing-provider-l1-1-0.dll should forward there. 
    // Hooking advapi32 catches both unless the binary imported directly from the api-set, in which case extend this.

    iat_hook_all("advapi32.dll", "EventRegister", (void *)stub_EventRegister, (void **)&orig_EventRegister);
    iat_hook_all("advapi32.dll", "EventUnregister", (void *)stub_EventUnregister, (void **)&orig_EventUnregister);
    iat_hook_all("advapi32.dll", "EventWrite", (void *)stub_EventWrite, (void **)&orig_EventWrite);
    iat_hook_all("advapi32.dll", "EventEnabled", (void *)stub_EventEnabled, (void **)&orig_EventEnabled);
    iat_hook_all("advapi32.dll", "EventWriteEx", (void *)stub_EventWriteEx, NULL);
    iat_hook_all("advapi32.dll", "EventWriteTransfer", (void *)stub_EventWriteTransfer, NULL);
    iat_hook_all("advapi32.dll", "EventActivityIdControl", (void *)stub_EventActivityIdControl, NULL);
    iat_hook_all("advapi32.dll", "EventProviderEnabled", (void *)stub_EventProviderEnabled, NULL);
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventWriteEx", (void *)stub_EventWriteEx, NULL);
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventWriteTransfer", (void *)stub_EventWriteTransfer, NULL);
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventActivityIdControl", (void *)stub_EventActivityIdControl, NULL);
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventProviderEnabled", (void *)stub_EventProviderEnabled, NULL);

    // Same names on the api-set
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventRegister", (void *)stub_EventRegister, NULL);
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventWrite", (void *)stub_EventWrite, NULL);
    iat_hook_all("api-ms-win-eventing-provider-l1-1-0.dll", "EventUnregister", (void *)stub_EventUnregister, NULL);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID rsv) {
    (void)rsv;
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        install();
    }
    return TRUE;
}

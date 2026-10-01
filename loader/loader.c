#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static void die(const char *msg)
{
    fprintf(stderr, "[loader] FATAL: %s (err=%lu)\n", msg, GetLastError());
    ExitProcess(1);
}

static int inject_dll(HANDLE proc, HANDLE primary_thread, LPCWSTR dll_path, LPTHREAD_START_ROUTINE load_library_w)
{
    SIZE_T path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(proc, NULL, path_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
    {
        fprintf(stderr, "[loader] VirtualAllocEx failed\n");
        return 0;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, remote, dll_path, path_bytes, &written) ||
        written != path_bytes)
    {
        fprintf(stderr, "[loader] WriteProcessMemory failed\n");
        return 0;
    }

    HANDLE thread = CreateRemoteThread(proc, NULL, 0, load_library_w, remote, 0, NULL);
    if (!thread)
    {
        fprintf(stderr, "[loader] CreateRemoteThread failed\n");
        return 0;
    }
    // Wait for LoadLibraryW to finish so the shim is fully attached before the primary thread resumes.
    WaitForSingleObject(thread, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    (void)primary_thread;

    if (exit_code == 0)
    {
        char ascii[512];
        WideCharToMultiByte(CP_UTF8, 0, dll_path, -1, ascii, sizeof(ascii), NULL, NULL);
        fprintf(stderr, "[loader] WARN: LoadLibraryW returned NULL for %s\n", ascii);
        return 0;
    }
    return 1;
}

int wmain(int argc, wchar_t **argv)
{
    // Find the "--" separator.
    int sep = -1;
    for (int i = 1; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--") == 0)
        {
            sep = i;
            break;
        }
    }
    if (argc < 4 || sep < 2 || sep + 1 >= argc)
    {
        fprintf(stderr, "usage: loader.exe <dll1>[;<dll2>...] -- <target.exe> [args...]\n");
        return 2;
    }

    wchar_t *shim_list = argv[1];
    wchar_t *target_exe = argv[sep + 1];

    // Rebuild the target command line: "target.exe" arg1 arg2 ...
    wchar_t cmdline[8192] = {0};
    int pos = 0;
    pos += swprintf(cmdline + pos, 8192 - pos, L"\"%ls\"", target_exe);
    for (int i = sep + 2; i < argc; i++)
    {
        pos += swprintf(cmdline + pos, 8192 - pos, L" \"%ls\"", argv[i]);
    }

    // LoadLibraryW lives at the same address in our kernel32 as in the target's, since Wine maps system DLLs at fixed bases per session.
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32)
        die("GetModuleHandleW(kernel32) failed");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    if (!pLoadLibraryW)
        die("GetProcAddress(LoadLibraryW) failed");

    STARTUPINFOW si = {.cb = sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(target_exe, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        die("CreateProcessW failed");

    // Iterate semicolon-separated shim list. mingw-w64 wcstok is the legacy 2-arg form; use wcstok_s for the safe state-passing one.
    wchar_t *ctx = NULL;
    for (wchar_t *tok = wcstok_s(shim_list, L";", &ctx);
         tok != NULL;
         tok = wcstok_s(NULL, L";", &ctx))
    {
        if (!inject_dll(pi.hProcess, pi.hThread, tok, pLoadLibraryW))
        {
            fprintf(stderr, "[loader] inject failed for %ls — aborting\n", tok);
            TerminateProcess(pi.hProcess, 1);
            return 3;
        }
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)exit_code;
}

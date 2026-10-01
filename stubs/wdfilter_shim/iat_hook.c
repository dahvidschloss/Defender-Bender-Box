#include <windows.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>
#include "iat_hook.h"

// Simple case-insensitive string comparison for DLL names
static int strieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}


// This funciton is the hooking engine. 
void *iat_hook(HMODULE module, const char *target_dll, const char *target_name, void *replacement)
{
    // If no module provided, target main .exe 
    if (!module) module = GetModuleHandleA(NULL);
    BYTE *base = (BYTE *)module;

    // Malware time, check and grab the DOS header. Make sure its real
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    // Now go to the NT Header, where the actual PE info lives
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Locate the Import Directory
    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) return NULL;

    // Start looping through the descriptors for DLLs
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp_rva);

    void *original = NULL;
    
    // Now for each DLL
    for (; desc->Name; desc++) 
    {
        // Get the name of the current DLL in the list
        const char *dll = (const char *)(base + desc->Name);
        if (!strieq(dll, target_dll)) continue;

        // Find the Thunks
        // OriginalFirstThunk = the name fo the functions
        IMAGE_THUNK_DATA *orig_thunk = (IMAGE_THUNK_DATA *) (base + desc->OriginalFirstThunk);
        // FirstThunk = The actual memory addresses where the funcitons live
        IMAGE_THUNK_DATA *iat_thunk = (IMAGE_THUNK_DATA *) (base + desc->FirstThunk);

        // Now we want to loop through every function imported from the DLL
        for (; orig_thunk->u1.AddressOfData; orig_thunk++, iat_thunk++) 
        {
            // Check if the function is imported via Ordinals instead of name. If so skip it.
            if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue; 

            // So then find the name of the funciton 
            IMAGE_IMPORT_BY_NAME *name = (IMAGE_IMPORT_BY_NAME *) (base + orig_thunk->u1.AddressOfData);
            if (strcmp((char *)name->Name, target_name) != 0) continue;

            //Once found swap the address and perms
            DWORD old_prot;
            //Since in memory IAT is usually RO we want to force it to RW perms
            VirtualProtect(&iat_thunk->u1.Function, sizeof(void *), PAGE_READWRITE, &old_prot);
            // Save the OG address so we can call it later in life
            original = (void *)(uintptr_t)iat_thunk->u1.Function;
            // This is the switcheroo. Replace the OG with our hooked function address
            iat_thunk->u1.Function = (uintptr_t)replacement;
            // Return to the original memory protections of the OG
            VirtualProtect(&iat_thunk->u1.Function, sizeof(void *), old_prot, &old_prot);
        }
    }
    return original;
}


// This funciton makes sure we don't miss any DLLS for what we need in our hooking funciotn
void iat_hook_all(const char *target_dll, const char *target_name, void *replacement, void **out_original)
{
    HMODULE mods[512];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();

    // First we get a list of every single DLL currently loaded in the process provided
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return;

    DWORD count = needed / sizeof(HMODULE);
    // Then for every loaded DLL, run the iat-Hook funciton
    for (DWORD i = 0; i < count; i++) 
    {
        void *orig = iat_hook(mods[i], target_dll, target_name, replacement);
        // if this is the first time we found the real address, make sure to save it later for our caller. 
        if (orig && out_original && !*out_original) *out_original = orig;
    }
}

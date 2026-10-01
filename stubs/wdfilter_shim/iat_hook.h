#ifndef IAT_HOOK_H
#define IAT_HOOK_H

#include <windows.h>

void *iat_hook(HMODULE module, const char *target_dll, const char *target_name, void *replacement);

// For convenience, hook in every loaded module.
void iat_hook_all(const char *target_dll, const char *target_name, void *replacement, void **out_original);

#endif

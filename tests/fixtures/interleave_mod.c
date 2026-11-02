/* The module interleave.c loads, unloads and loads again at another base. */
#include <windows.h>
__declspec(dllexport) __declspec(noinline) int fx_mod_value(int input) { return input * 11 + 77; }
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) { (void)module; (void)reason; (void)reserved; return TRUE; }

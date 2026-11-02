/* The DLL that trace_app.c loads. Built twice (-DPLUGIN_ID=1 and 2) as trace_plugin_1.dll / trace_plugin_2.dll;
   trace_app stages them as plug\dir_a\trace_plugin.dll and plug\dir_b\trace_plugin.dll, so the DLL search order
   decides which one a LoadLibrary("trace_plugin.dll") gets. */
#include <windows.h>
#ifndef PLUGIN_ID
#define PLUGIN_ID 1
#endif
__declspec(dllexport) __declspec(noinline) int fx_plugin_id(void) { return PLUGIN_ID; }
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) { (void)module; (void)reason; (void)reserved; return TRUE; }

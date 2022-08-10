// dllmain.cpp : Definiuje punkt wejścia dla aplikacji DLL.
#include <Windows.h>
#include <tchar.h>
#include <vector>
#include <string>
#include "potato.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    AllocConsole();

    TCHAR file_name[MAX_PATH + 1] = { 0 };
    GetModuleFileName(NULL, &file_name[0], MAX_PATH);
    DWORD pid = GetCurrentProcessId();
   

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        write_console(_T("[*]. Nazywam sie potato i jestem z procesu: %s pid:%d\r\n"), file_name, pid);
     
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


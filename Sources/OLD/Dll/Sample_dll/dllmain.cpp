// dllmain.cpp : Definiuje punkt wejścia dla aplikacji DLL.
#include "pch.h"

INT is_32bit() {

    BOOL wow = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow) == FALSE) {
        return -1;
    }
    if (wow == TRUE) {
        return 1;
    }
    return 0;

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    INT is_32bit_app = is_32bit();

    if (is_32bit_app == 1) {   /*No x64 subsystem, */
       //LdrLoadDll(user32.dll)
       //LdrGetProc(MessageBox)
       //Call messageBOX 
       //or 
       //Haven's gate
       // MessageBox(0, _T("I'm 64bit dll in a 32bit (wow) process!"), _T("I'm 64bit dll in a 32bit (wow) process!"), 0);
    } else if(is_32bit_app == 0) {
        MessageBox(0, _T("I'm 64bit dll in a 64bit process!"), _T("I'm 64bit dll in a 64bit process!"), 0);
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include<Windows.h>
#include<atlstr.h>

LPCWSTR TargetDll = L"USER32.dll";
FARPROC TargetFun;
CString strTmp;

BOOL HookIat(FARPROC Target, FARPROC HookFun){

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		HMODULE hDll = GetModuleHandle(TargetDll);
		if (!hDll) {
			strTmp.Format(L"GetModuleHandle Error:%c ",GetLastError());
			MessageBox(NULL, strTmp, L"Error", MB_OK);
		}
		TargetFun =GetProcAddress(hDll, "SetWindowTextW");//保存函数地址
		if (!TargetFun) {
			strTmp.Format(L"GetProcAddress Error:%c ", GetLastError());
			MessageBox(NULL, strTmp, L"Error", MB_OK);
		}

		HookIat();
		break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include<Windows.h>
#include<atlstr.h>

LPCWSTR TargetDll = L"USER32.dll";
FARPROC TargetFun;
CString strTmp;

BOOL HookIat(LPCTSTR szDllname,FARPROC Target, FARPROC HookFun){
	HMODULE hMod;
	LPCTSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImage;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

	hMod = GetModuleHandle(szDllname);
	pAddr = (PBYTE) hMod;

	pAddr += *((DWORD*)&pAddr[0x3C]);
	dwRVA = *((DWORD*)&pAddr[0x80]);

	pImage = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

	for (; pImage->Name; pImage++) {
		szLibName = (LPCTSTR)((DWORD)hMod + pImage->Name);
		if (!StrCmp(szLibName, szDllname)) {
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImage->FirstThunk);
			for (; pThunk->u1.Function; pThunk++) {
				if (pThunk->u1.Function == (DWORD)Target) {
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
					pThunk->u1.Function = (DWORD)HookFun;
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
					return TRUE;
				}
			}
		}
	}
	
	return FALSE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HMODULE hDll = GetModuleHandle(TargetDll);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		
		if (!hDll) {
			strTmp.Format(L"GetModuleHandle Error:%c ",GetLastError());
			MessageBox(NULL, strTmp, L"Error", MB_OK);
		}
		TargetFun =GetProcAddress(hDll, "SetWindowTextW");//保存函数地址
		if (!TargetFun) {
			strTmp.Format(L"GetProcAddress Error:%c ", GetLastError());
			MessageBox(NULL, strTmp, L"Error", MB_OK);
		}

		HookIat(TargetDll,TargetFun, TargetFun);
		break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


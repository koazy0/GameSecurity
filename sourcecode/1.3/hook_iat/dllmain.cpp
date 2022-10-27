// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include<Windows.h>
#include<atlstr.h>


FARPROC TargetFun;
CString strTmp;

BOOL HookIat(LPCTSTR szDllname,FARPROC Target, FARPROC HookFun){
	HMODULE hMod;
	LPCTSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pIDT;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE) hMod;

	pAddr += *((DWORD*)&pAddr[0x3C]);		//+offset(NT_Header)
	dwRVA = *((DWORD*)&pAddr[0x80]);		//+offset(IDT)

	pIDT = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);	//VA of Import Directory Table

	
	//在PE结构中，一张线性表结构总是以NULL结尾
	for (; pIDT->Name; pIDT++) {

		//hMod为模块基址，寻找目标DLL的IDT
		szLibName = (LPCTSTR)((DWORD)hMod + pIDT->Name);
		if (!StrCmp(szLibName, szDllname)) {
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pIDT->FirstThunk);
			for (; pThunk->u1.Function; pThunk++) {
				if (pThunk->u1.Function == (DWORD)Target) {
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);	//修改内存属性
					pThunk->u1.Function = (DWORD)HookFun;
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);			//恢复内存属性
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
	LPCTSTR TargetDll = "USER32.dll";
	HMODULE hDll = GetModuleHandle(TargetDll);
	
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		
		if (!hDll) {
			strTmp.Format("GetModuleHandle Error:%c ",GetLastError());
			MessageBox(NULL, strTmp, "Error", MB_OK);
		}
		TargetFun =GetProcAddress(hDll, "SetWindowTextW");//保存函数地址
		if (!TargetFun) {
			strTmp.Format("GetProcAddress Error:%c ", GetLastError());
			MessageBox(NULL, strTmp, "Error", MB_OK);
		}

		HookIat(TargetDll,TargetFun, TargetFun);//进行IAT hook
		break;

    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		HookIat(TargetDll, TargetFun, TargetFun);//取消IAT hook
        break;
    }
    return TRUE;
}


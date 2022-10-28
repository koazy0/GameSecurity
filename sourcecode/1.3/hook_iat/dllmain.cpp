#include "pch.h"
#include<Windows.h>
#include<iostream>
#include<atlstr.h>

LPCTSTR TargetDll = "USER32.dll";
typedef BOOL(WINAPI *TargetFun)(_In_ HWND hWnd, _In_opt_ LPCTSTR lpString);
TargetFun TargetProc;
CString strTmp;


using namespace std;

BOOL HookIat(LPCTSTR szDllname, FARPROC Target, FARPROC HookFun) {
	HMODULE hMod;
	LPCTSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImage;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwOldProtect1, dwRVA;
	PBYTE pAddr;

	hMod = GetModuleHandle(NULL);
	cout << "hMod:"<<hMod << endl;
	pAddr = (PBYTE)hMod;

	pAddr += *((DWORD*)&pAddr[0x3C]);	//+offset(NT_Header)
	dwRVA = *((DWORD*)&pAddr[0x80]);	//+offset(IDT)

	pImage = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);	//VA of Import Directory Table

	for (; pImage->Name; pImage++) {
		szLibName = (LPCTSTR)((DWORD)hMod + pImage->Name);
		if (!StrCmp(szLibName, szDllname)) {
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImage->FirstThunk);
			for (; pThunk->u1.Function; pThunk++) {
				if (pThunk->u1.Function == (DWORD)Target) {
					VirtualProtect((LPVOID)pThunk, 4, PAGE_EXECUTE_WRITECOPY, &dwOldProtect1);				//修改内存属性
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, PAGE_EXECUTE_WRITECOPY, &dwOldProtect);	//修改内存属性
					pThunk->u1.Function = (DWORD)HookFun;
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);			//恢复内存属性
					VirtualProtect((LPVOID)pThunk, 4, dwOldProtect1, &dwOldProtect1);			//恢复内存属性
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL WINAPI hello(HWND hWnd, LPCTSTR lpString) {
	DWORD dwOldProtect1;
	MessageBox(NULL, "hello world!", "Hello", MB_OK);
	MessageBox(NULL, lpString, "SetWindowText:lpString", MB_OK);
	VirtualProtect((LPVOID)TargetProc, 0x400, PAGE_EXECUTE_READWRITE, &dwOldProtect1);
	return TargetProc(hWnd, lpString);
}

BOOL WINAPI DllMain(HINSTANCE hinstDll,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	BOOL result;
	HMODULE hDll = GetModuleHandleA(TargetDll);
	if (!hDll) {
		strTmp.Format("GetModuleHandle Error:%c ", GetLastError());
		MessageBox(NULL, strTmp, "Error", MB_OK);
	}
	TargetProc = (TargetFun)GetProcAddress(hDll, "SetWindowTextW");//保存函数地址
	if (!TargetProc) {
		strTmp.Format("GetProcAddress Error:%c ", GetLastError());
		MessageBox(NULL, strTmp, "Error", MB_OK);
	}
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(NULL, "DLL_PROCESS_ATTACH!", "Hooked", MB_OK);
		
		result = HookIat(TargetDll, (FARPROC)TargetProc,(FARPROC)hello );
		
		if(result)
		MessageBox(NULL, "IAT Hook Success", "HookIat", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		MessageBox(NULL, "DLL_THREAD", "Hooked", MB_OK);
		break;
	case DLL_PROCESS_DETACH:
		MessageBox(NULL, "DLL_PROCESS_DETACH!", "Hooked", MB_OK);
		 result = HookIat(TargetDll,  (FARPROC)hello,(FARPROC)TargetProc);

		 if (result)
		 MessageBox(NULL, "IAT Hook Ended", "HookIat", MB_OK);

		break;
	}
	return TRUE;
}

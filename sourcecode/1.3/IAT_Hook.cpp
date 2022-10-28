//这是IAT_HOOK的示例代码(非注入，仅作结构参考)
//替换函数为SetWindowTextA  in USER32.dll
//显示为输出两个Msgbox,从而实现hook的效果

#include<Windows.h>
#include<iostream>
#include<atlstr.h>

//声明函数指针，用于保存原来的procaddress
//原函数为WINAPI，为了保持栈平衡需要保持相同的调用
typedef BOOL (WINAPI *TargetFun)(_In_ HWND hWnd, _In_opt_ LPCTSTR lpString);
LPCTSTR TargetDll = "USER32.dll";
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

BOOL WINAPI hello( HWND hWnd,  LPCTSTR lpString) {
	DWORD dwOldProtect1;
	cout << "hello world!\n";
	MessageBox(NULL, "hello world!", "Hello",MB_OK);
	MessageBox(NULL, lpString, "SetWindowText:lpString",MB_OK);
	VirtualProtect((LPVOID)TargetProc, 0x400, PAGE_EXECUTE_READWRITE, &dwOldProtect1);
	return TargetProc( hWnd ,lpString);
}


int main() {
	HMODULE hDll = GetModuleHandle(TargetDll);
	if (!hDll) {
		strTmp.Format("GetModuleHandle Error:%c ", GetLastError());
		MessageBox(NULL, strTmp, "Error", MB_OK);
	}
	TargetProc = (TargetFun)GetProcAddress(hDll, "SetWindowTextA");//保存函数地址
	if (!TargetProc) {
		strTmp.Format("GetProcAddress Error:%c ", GetLastError());
		MessageBox(NULL, strTmp, "Error", MB_OK);
	}

	BOOL result= HookIat(TargetDll, (FARPROC)TargetProc, (FARPROC)hello);
	cout << result<<endl;
	SetWindowText(NULL, "hello world!");
	result=HookIat(TargetDll, (FARPROC)hello, (FARPROC)TargetProc);
	cout << result << endl;
	
	return 0;
}

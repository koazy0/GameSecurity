//����IAT_HOOK��ʾ������(��ע�룬�����ṹ�ο�)
//�滻����ΪSetWindowTextA  in USER32.dll
//��ʾΪ�������Msgbox,�Ӷ�ʵ��hook��Ч��

#include<Windows.h>
#include<iostream>
#include<atlstr.h>

//��������ָ�룬���ڱ���ԭ����procaddress
//ԭ����ΪWINAPI��Ϊ�˱���ջƽ����Ҫ������ͬ�ĵ���
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
					VirtualProtect((LPVOID)pThunk, 4, PAGE_EXECUTE_WRITECOPY, &dwOldProtect1);				//�޸��ڴ�����
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, PAGE_EXECUTE_WRITECOPY, &dwOldProtect);	//�޸��ڴ�����
					pThunk->u1.Function = (DWORD)HookFun;
					VirtualProtect((LPVOID)pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);			//�ָ��ڴ�����
					VirtualProtect((LPVOID)pThunk, 4, dwOldProtect1, &dwOldProtect1);			//�ָ��ڴ�����
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
	TargetProc = (TargetFun)GetProcAddress(hDll, "SetWindowTextA");//���溯����ַ
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

// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include<atlstr.h>
#include<Windows.h>
#include<iostream>
HHOOK keyborad_hook = NULL;
CString strTmp;
HINSTANCE hInstance;




LRESULT CALLBACK KeyboradProc(int nCode, WPARAM wParam, LPARAM lParam) {
	
	//wParam只与大写键盘有关
	strTmp.Format("wParam:%c ", wParam);
	if (nCode == 0) {
		if ((lParam & 0x80000000)&& wParam != 'q'&& wParam != 'Q') {	//lParam按下键为0，释放为1
			MessageBox(NULL, strTmp, "KeyBoradHook", MB_OK);
			return 1;	//不传递给下一个处理函数
		}
	}
	return CallNextHookEx(keyborad_hook, nCode, wParam, lParam);
}

extern "C" __declspec(dllexport) void HookStart() {
	keyborad_hook=SetWindowsHookEx(WH_KEYBOARD, KeyboradProc,hInstance,0);
	if (!keyborad_hook) {
		std::cout << "SetWinhook Error!code: " << GetLastError() << std::endl;
	}
}

extern "C" __declspec(dllexport) void HookStop() {
	if (!UnhookWindowsHookEx(keyborad_hook)) {
		std::cout << "Unhook Error!code: " << GetLastError() << std::endl;
	};
	keyborad_hook = NULL;
}


BOOL WINAPI DllMain( HINSTANCE hinstDll,HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	hInstance = hinstDll;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		hInstance = hinstDll;
		std::cout << "hInstance: " << hInstance << std::endl;
		std::cout << "GetModuleHandle(NULL): " << GetModuleHandle(NULL) << std::endl;
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


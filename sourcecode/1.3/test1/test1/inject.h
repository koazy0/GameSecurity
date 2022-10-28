#pragma once
#include<iostream>
#include<Windows.h>
#include "tlhelp32.h"
#include<vector>
#include<atlstr.h>
#include<conio.h>

#define FILE "clock.exe"
#define DLL	 "my.dll"
#define DLL_IAT	 "hook_iat.dll"
#ifndef WORK 
#define WORK 1 

#endif

//定义两个函数指针
typedef void(*Hook_HookStart) ();
typedef Hook_HookStart Hook_HookStop;


BOOL InjectByCreateRemoteThread();
BOOL InjectByApc();
BOOL InjectByHook();
BOOL GetTidFromProcess(HANDLE,std::vector<DWORD>&);
HANDLE GetHandleFromName(char *name);
DWORD GetProcessIdFromName(char *name);
BOOL UnloadModule(HANDLE Filehandle, LPCSTR Dllname);
void PrintTids(std::vector<DWORD>);

//钩子回调函数；不论安装什么类型的钩子，hook函数原型都是一样的
LRESULT CALLBACK KeyboradProc(int nCode, WPARAM wParam, LPARAM lParam);
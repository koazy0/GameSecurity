#include"inject.h"


//���ݽ�������ȡhandle

char file[] = "scanf.exe";
//���ݽ�������ȡpid

CString strTmp;
DWORD pid;
HHOOK keyborad_hook = NULL;

int main() {
	//InjectByCreateRemoteThread();
	//InjectByApc();
	/*if (!InjectByHook()) {
		MessageBox(NULL, "Error", "HookError", MB_OK);
	};*/
	system("pause");
	return 0;
}

BOOL InjectByCreateRemoteThread() {
	//��ʼ���ṹ_SECURITY_ATTRIBUTES
	_SECURITY_ATTRIBUTES security_attributes = { sizeof(_SECURITY_ATTRIBUTES),NULL,FALSE };
	HANDLE target = GetHandleFromName(file);

	LPVOID writemem = VirtualAllocEx(target, NULL, sizeof(DLL), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(target, writemem, DLL, sizeof(DLL), 0);

	DWORD tid;
	HANDLE re = CreateRemoteThread(
		target,
		&security_attributes,
		0,
		(LPTHREAD_START_ROUTINE)LoadLibrary,
		writemem,
		0,
		&tid
	);
	return TRUE;
}

BOOL InjectByApc() {
	HANDLE target = GetHandleFromName(file);
	std::vector<DWORD>tids;

	//д�����
	auto writemem = VirtualAllocEx(target, NULL, sizeof(DLL), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(target, writemem, DLL, sizeof(DLL), 0);

	//���̣߳�����apc���
	HANDLE thread;
	GetTidFromProcess(target, tids);
	std::cout << "count of tids:"<<tids.size() << std::endl;
	for (unsigned int i = 0; i < tids.size(); i++) {
		//std::cout << tids[i]<<std:: endl;
		thread = OpenThread(PROCESS_ALL_ACCESS, FALSE, tids[i]);
		if (thread) {
			QueueUserAPC((PAPCFUNC)LoadLibraryA, thread, (ULONG_PTR)writemem);
		}
		else 
			std::cout << "OpenThread Error:code "<<GetLastError() << std::endl;
	}

	//���������ͷŷ�ʽ�ȼ�
	VirtualFreeEx(target, writemem, 0, MEM_RELEASE);
	//VirtualFreeEx(target, writemem, sizeof(DLL), MEM_DECOMMIT);

	return TRUE;
}

BOOL InjectByHook() {
	HMODULE hDll = LoadLibrary("hook.dll");

	if (!hDll) {
		std::cout << "LoadLibrary Error!code: " << GetLastError() << std::endl;
	}

	Hook_HookStart HookStart = (Hook_HookStart)GetProcAddress(hDll, "HookStart");
	Hook_HookStop HookStop = (Hook_HookStop)GetProcAddress(hDll, "HookStop");

	std::cout << "hDll:" << hDll << std::endl;
	std::cout << "HookStart:" << HookStart << std::endl;
	std::cout << "HookStop:" << HookStop << std::endl;
	if ((!HookStart)|| (!HookStop)) {
		std::cout << "GetProcAddress Error!code: " << GetLastError() << std::endl;
		return FALSE;
	}

	HookStart();
	while ((_getch() != 'q')&&(_getch() != 'Q'));
	HookStop();
	FreeLibrary(hDll);
	
	return TRUE;
}



//�õ�һ�����̵�����ThreadId
BOOL GetTidFromProcess(HANDLE process, std::vector<DWORD>&tids) {
	HANDLE  hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Error!\n");
		return 2;
	}
	THREADENTRY32 TE = { sizeof(THREADENTRY32) };

	while (Thread32Next(hsnapshot, &TE)) {
		if(TE.th32OwnerProcessID==pid)
		tids.push_back(TE.th32ThreadID);
	}
	return TRUE;
}


HANDLE GetHandleFromName(char *name) {
	pid = GetProcessIdFromName(name);
	//std::cout << pid << std::endl;
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!handle) {
		std::cout << "last error code:" << GetLastError() << std::endl;
		return NULL;
	}
	return handle;
}

DWORD GetProcessIdFromName(char *name)
{
	HANDLE  hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//������ǰ���̿���
	
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Error!\n");
		return 1;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	//�������̣��ԱȽ�����
	while (Process32Next(hsnapshot, &pe)) {
		//std::cout << pe.szExeFile <<std::endl;
		if (!strcmp(pe.szExeFile, name))
		{
			return pe.th32ProcessID;
		}

	}
	CloseHandle(hsnapshot);
	return 0;
}

BOOL UnloadModule(HANDLE Filehandle, LPCSTR Dllname) {
	HANDLE  hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);//������ǰ���̿���
	
	if (hsnapshot == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Error!\n");
		return 2;
	}
	MODULEENTRY32 me = {sizeof(MODULEENTRY32)};
	
	while (Module32Next(hsnapshot, &me)) {
		if (!strcmp(me.szModule, DLL)) {
			HANDLE target_handle = me.hModule;
			std::cout << me.szModule << std::endl;
			break;
		}
		//else std::cout<< me.szModule <<std::endl;
	}
	//HANDLE hThread=CreateRemoteThread(Filehandle, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, &me.szModule, 0, NULL);
	/*HANDLE hThread= CreateRemoteThread(Filehandle, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetModuleHandleA, (LPVOID)&DLL, 0, 0);
	if(!hThread)
		std::cout <<GetLastError()<< std::endl;
	
	GetExitCodeThread(hThread, &dwHandle);*/
	DWORD dwHandle;
	HANDLE hThread = CreateRemoteThread(Filehandle, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, me.modBaseAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &dwHandle);
	std::cout << dwHandle << std::endl;

	return TRUE;
}

void PrintTids(std::vector<DWORD> tids) {
	std::cout << "tids:"<< tids.size() << std::endl;
	for (unsigned int i = 0; i < tids.size(); i++) {
		std::cout << tids[i]<< std::endl;
	}
}


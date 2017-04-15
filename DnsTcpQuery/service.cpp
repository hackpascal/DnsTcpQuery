#include "stdafx.h"

SERVICE_STATUS m_ServiceStatus;
SERVICE_STATUS_HANDLE m_ServiceStatusHandle;
DWORD m_dwCurrentStatus;

HANDLE hStopEvent;
HANDLE hListen4Stopped;
HANDLE hListen6Stopped;
HANDLE hConnCheckStopped;
HANDLE ThreadEvents[3];
HANDLE hMutex;

WSADATA wsaData = {0};

const LPTSTR lpServiceName = _T("DnsTcpQuery");
const LPTSTR lpServiceDisplayName = _T("QueryDNSviaTCP");
const LPTSTR lpServiceDescription = _T("将 Windows 的 DNS 查询转发为 TCP DNS 查询。启动此服务后请将本机 DNS 地址改为 127.0.0.1 或 ::1");

bool MainService()
{
	SERVICE_TABLE_ENTRY ste[2] = {};
	ste[0].lpServiceName = lpServiceName;
	ste[0].lpServiceProc = ServiceMain;

	return StartServiceCtrlDispatcher(ste) != 0;
}

void ChangeServiceStatus(DWORD dwServiceStatus)
{
	m_ServiceStatus.dwCurrentState = dwServiceStatus;
	SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
	m_dwCurrentStatus = dwServiceStatus;
}

VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPTSTR *lpServiceArgVectors)
{
	PrintString(NULL, "\n");
	m_ServiceStatus.dwServiceType = SERVICE_WIN32;
	m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	m_ServiceStatus.dwWin32ExitCode = NO_ERROR;
	m_ServiceStatus.dwServiceSpecificExitCode = NO_ERROR;
	m_ServiceStatus.dwCheckPoint = 0;
	m_ServiceStatus.dwWaitHint = 0;

	m_ServiceStatusHandle = RegisterServiceCtrlHandler(lpServiceName, ServiceControlHandler);

	if(!m_ServiceStatusHandle)
		return;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	read_param();
	
	PrintString(NULL, "默认 IPv4 DNS 服务器：%s\n", lpDNSAddr4);
	PrintString(NULL, "默认 IPv6 DNS 服务器：%s\n", lpDNSAddr6);
	PrintString(NULL, "\n");

	hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	hListen4Stopped = CreateEvent(NULL, TRUE, FALSE, NULL);
	hListen6Stopped = CreateEvent(NULL, TRUE, FALSE, NULL);
	hConnCheckStopped = CreateEvent(NULL, TRUE, FALSE, NULL);
	hMutex = CreateMutex(NULL, FALSE, NULL);

	init_cache_lock();

	ChangeServiceStatus(SERVICE_RUNNING);

	ThreadEvents[0] = hListen4Stopped;
	ThreadEvents[1] = hListen6Stopped;
	ThreadEvents[2] = hConnCheckStopped;

	thread_data thread_v4, thread_v6, thread_conn;

	thread_v4.Family = AF_INET;
	thread_v4.hStopEvent = hStopEvent;
	thread_v4.hStoppedEvent = hListen4Stopped;
	thread_v4.hMutex = hMutex;

	thread_v6.Family = AF_INET6;
	thread_v6.hStopEvent = hStopEvent;
	thread_v6.hStoppedEvent = hListen6Stopped;
	thread_v6.hMutex = hMutex;

	thread_conn.hStopEvent = hStopEvent;
	thread_conn.hStoppedEvent = hConnCheckStopped;
	
	//先运行一次
	run_connection_check();
	_beginthread(connection_check, 0, (void*)&thread_conn);
	_beginthread(query_listen, 0, (void*)&thread_v4);
	_beginthread(query_listen, 0, (void*)&thread_v6);

	//服务主循环
	while(m_dwCurrentStatus != SERVICE_STOPPED)
	{
		if(WaitForMultipleObjects(3, ThreadEvents, TRUE, 0) != WAIT_TIMEOUT)
		{
			ChangeServiceStatus(SERVICE_STOPPED);
			break;
		}
		Sleep(1000);
	}

	CloseHandle(hStopEvent);
	CloseHandle(hListen4Stopped);
	CloseHandle(hListen6Stopped);
	CloseHandle(hConnCheckStopped);
	CloseHandle(hMutex);

	delete_cache_lock();

	clear_rules();

	WSACleanup();

	return;
}

bool MainDebug()
{
	PrintString(NULL, "\n");
	SetConsoleCtrlHandler(DebugControlHandler, TRUE);

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	read_param();

	PrintString(NULL, "默认 IPv4 DNS 服务器：%s\n", lpDNSAddr4);
	PrintString(NULL, "默认 IPv6 DNS 服务器：%s\n", lpDNSAddr6);
	PrintString(NULL, "\n");

	hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	hListen4Stopped = CreateEvent(NULL, TRUE, FALSE, NULL);
	hListen6Stopped = CreateEvent(NULL, TRUE, FALSE, NULL);
	hConnCheckStopped = CreateEvent(NULL, TRUE, FALSE, NULL);
	hMutex = CreateMutex(NULL, FALSE, NULL);

	init_cache_lock();

	ThreadEvents[0] = hListen4Stopped;
	ThreadEvents[1] = hListen6Stopped;
	ThreadEvents[2] = hConnCheckStopped;

	thread_data thread_v4, thread_v6, thread_conn;

	thread_v4.Family = AF_INET;
	thread_v4.hStopEvent = hStopEvent;
	thread_v4.hStoppedEvent = hListen4Stopped;
	thread_v4.hMutex = hMutex;

	thread_v6.Family = AF_INET6;
	thread_v6.hStopEvent = hStopEvent;
	thread_v6.hStoppedEvent = hListen6Stopped;
	thread_v6.hMutex = hMutex;
	
	thread_conn.hStopEvent = hStopEvent;
	thread_conn.hStoppedEvent = hConnCheckStopped;
	
	//先运行一次
	run_connection_check();
	_beginthread(connection_check, 0, (void*)&thread_conn);
	_beginthread(query_listen, 0, (void*)&thread_v4);
	_beginthread(query_listen, 0, (void*)&thread_v6);

	while(true)
	{
		if(WaitForMultipleObjects(3, ThreadEvents, TRUE, 0) != WAIT_TIMEOUT)
		{
			break;
		}

		Sleep(1000);
	}

	CloseHandle(hStopEvent);
	CloseHandle(hListen4Stopped);
	CloseHandle(hListen6Stopped);
	CloseHandle(hConnCheckStopped);
	CloseHandle(hMutex);

	delete_cache_lock();

	clear_rules();

	WSACleanup();

	return true;
}

VOID WINAPI ServiceControlHandler(DWORD dwControl)
{
	switch(dwControl)
	{
	case SERVICE_CONTROL_STOP:
		ChangeServiceStatus(SERVICE_STOP_PENDING);
		SetEvent(hStopEvent);
		WaitForMultipleObjects(3, ThreadEvents, TRUE, 6000);
		m_ServiceStatus.dwWin32ExitCode = NO_ERROR;
		ChangeServiceStatus(SERVICE_STOPPED);
	}
}

BOOL WINAPI DebugControlHandler(DWORD dwCtrlType)
{
	switch(dwCtrlType)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
		SetEvent(hStopEvent);
		WaitForMultipleObjects(3, ThreadEvents, TRUE, 6000);
		return TRUE;
	}
	return FALSE;
}


bool InstallNTService()
{

	char lpImage[512], lpFileName[512];
	DWORD nameLen = GetModuleFileName(0, lpFileName, 512);
	
	lpFileName[nameLen] = 0;
	memset(lpImage, 0, 512);
	sprintf_s(lpImage, 512, "\"%s\" service", lpFileName);

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if(!hSCManager)
	{
		printf("OpenSCManager 失败，LastError = %d\n", GetLastError());
		return false;
	}

	SC_HANDLE hService = CreateService(
		hSCManager,
		lpServiceName,
		lpServiceDisplayName,
		SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		lpImage,
		NULL,
		NULL,
		NULL,
		"NT AUTHORITY\\NetworkService",
		NULL);

	if(!hService)
	{
		printf("CreateService 失败，LastError = %d\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return false;
	}

	ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&lpServiceDescription);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return true;
}

bool RemoveNTService()
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

	if(!hSCManager)
	{
		printf("OpenSCManager 失败，LastError = %d\n", GetLastError());
		return false;
	}

	SC_HANDLE hService = OpenService(hSCManager, lpServiceName, SERVICE_ALL_ACCESS);

	if(!hService)
	{
		printf("OpenService 失败，LastError = %d\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return false;
	}

	BOOL result = DeleteService(hService);

	if(!result)
		printf("DeleteService 失败，LastError = %d\n", GetLastError());

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return result != 0;
}
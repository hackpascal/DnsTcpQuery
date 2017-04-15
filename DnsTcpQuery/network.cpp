#include "stdafx.h"

bool bIPv4Enabled = false;
bool bIPv6Enabled = false;
HANDLE hOpMutex = NULL;

bool is_real_adapter(char *adapter_name);
int ping4(in_addr addr);
int ping6(in6_addr addr);

void set_ipv4_enable(bool state);
void set_ipv6_enable(bool state);

void connection_check(void *data)
{
	thread_data *p = (thread_data *)data;

	hOpMutex = CreateMutex(NULL, FALSE, NULL);

	while(WaitForSingleObject(p->hStopEvent, 10000) == WAIT_TIMEOUT)
		run_connection_check();

	CloseHandle(hOpMutex);

	SetEvent(p->hStoppedEvent);
}

int run_connection_check()
{
	int Family = AF_UNSPEC;
	PIP_ADAPTER_ADDRESSES pAddresses = NULL, pCurrAddresses;
	PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;
	ULONG pOutBufLen = 0;
	ULONG uFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
	sockaddr_in *addr4;
	sockaddr_in6 *addr6;

	set_ipv4_enable(true);
	set_ipv6_enable(true);

	if(GetAdaptersAddresses(Family, uFlags, NULL, pAddresses, &pOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		
		pAddresses = (PIP_ADAPTER_ADDRESSES)new char[pOutBufLen];
		if(GetAdaptersAddresses(Family, uFlags, NULL, pAddresses, &pOutBufLen) != ERROR_SUCCESS)
		{
			delete [] (char*)pAddresses;
			return false;
		}

		set_ipv4_enable(false);
		set_ipv6_enable(false);

		pCurrAddresses = pAddresses;

		while(pCurrAddresses)
		{
			if(is_real_adapter(pCurrAddresses->AdapterName))
			{
				pGateway = pCurrAddresses->FirstGatewayAddress;
				while(pGateway)
				{						
					if(pGateway->Address.lpSockaddr->sa_family == AF_INET)
					{
						if(!ipv4_enabled())
						{
							addr4 = (sockaddr_in*)pGateway->Address.lpSockaddr;
							if(ping4(addr4->sin_addr) >= 0)
								set_ipv4_enable(true);
						}
					}
					else
					{
						if(!ipv6_enabled())
						{
							addr6 = (sockaddr_in6*)pGateway->Address.lpSockaddr;
							if(ping6(addr6->sin6_addr) >= 0)
								set_ipv6_enable(true);
						}
					}

					pGateway = pGateway->Next;
				}
			}
			pCurrAddresses = pCurrAddresses->Next;
		}

		delete [] (char*)pAddresses;

		if(!ipv4_enabled() && !ipv6_enabled())
		{
			set_ipv4_enable(true);
			set_ipv6_enable(true);
		}

		return true;
	}

	return false;
}

bool is_real_adapter(char *adapter_name)
{
	HKEY hAdapt;
	char adapter[256];
	char *device;
	DWORD dwType, dwSize, dwRetVal;
	bool result;

	adapter[0] = 0;
	sprintf_s(adapter, 256, "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", adapter_name);

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, adapter, 0, KEY_READ, &hAdapt) != ERROR_SUCCESS)
		return false;

	device = (char*)malloc(256);
	dwSize = 256;
	if((dwRetVal = RegQueryValueEx(hAdapt, "PnpInstanceID", NULL, &dwType, (LPBYTE)device, &dwSize)) != ERROR_SUCCESS)
	{
		if(dwRetVal == ERROR_MORE_DATA)
		{
			device = (char*)realloc(device, dwSize);
			if(RegQueryValueEx(hAdapt, "PnPInstanceId", NULL, &dwType, (LPBYTE)device, &dwSize) == ERROR_SUCCESS)
				goto _Continue;
		}
		free(device);
		RegCloseKey(hAdapt);
		return false;
	}

_Continue:

	result = false;
	if(!_strnicmp(device, "PCI", 3))
		result = true;

	free(device);
	RegCloseKey(hAdapt);

	return result;
}

int ping4(in_addr addr)
{
	HANDLE hIcmpFile;
	IPAddr DestAddr;
	DWORD dwRetVal;
	char SendData[32];
	DWORD ReplySize;
	char *ReplyBuffer;
	PICMP_ECHO_REPLY pEchoReply;
	int result;

	hIcmpFile = IcmpCreateFile();
	if(hIcmpFile == INVALID_HANDLE_VALUE)
		return -1;

	ReplySize = sizeof SendData + sizeof ICMP_ECHO_REPLY;

	ReplyBuffer = new char[ReplySize];
	memcpy(&DestAddr, &addr, 4);
	dwRetVal = IcmpSendEcho2(hIcmpFile, NULL, NULL, NULL, DestAddr, SendData, sizeof SendData, NULL, ReplyBuffer, ReplySize, 1000);

	if(dwRetVal)
	{
		pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
		result = pEchoReply->RoundTripTime;
	}
	else
		result = -1;

	delete [] ReplyBuffer;

	IcmpCloseHandle(hIcmpFile);

	return result;
}

int ping6(in6_addr addr)
{
	HANDLE hIcmpFile;
	sockaddr_in6 DestAddr, SrcAddr;
	DWORD dwRetVal;
	char SendData[32];
	DWORD ReplySize;
	char *ReplyBuffer;
	PICMPV6_ECHO_REPLY pEchoReply;
	int result;

	hIcmpFile = Icmp6CreateFile();
	if(hIcmpFile == INVALID_HANDLE_VALUE)
		return -1;

	ReplySize = sizeof SendData + sizeof ICMPV6_ECHO_REPLY;

	ReplyBuffer = new char[ReplySize];

	memset(&DestAddr, 0, sizeof DestAddr);
	memset(&SrcAddr, 0, sizeof SrcAddr);

	DestAddr.sin6_family = AF_INET6;
	memcpy(&DestAddr.sin6_addr, &addr, sizeof addr);

	dwRetVal = Icmp6SendEcho2(hIcmpFile, NULL, NULL, NULL, &SrcAddr, &DestAddr, SendData, sizeof SendData, NULL, ReplyBuffer, ReplySize, 1000);

	if(dwRetVal)
	{
		pEchoReply = (PICMPV6_ECHO_REPLY)ReplyBuffer;
		result = pEchoReply->RoundTripTime;
	}
	else
		result = -1;

	delete [] ReplyBuffer;

	IcmpCloseHandle(hIcmpFile);

	return result;
}

bool ipv4_enabled()
{
	if(hOpMutex) WaitForSingleObject(hOpMutex, INFINITE);
	bool result = bIPv4Enabled;
	if(hOpMutex) ReleaseMutex(hOpMutex);
	return result;
}

bool ipv6_enabled()
{
	if(hOpMutex) WaitForSingleObject(hOpMutex, INFINITE);
	bool result = bIPv6Enabled;
	if(hOpMutex) ReleaseMutex(hOpMutex);
	return result;
}

void set_ipv4_enable(bool state)
{
	if(hOpMutex) WaitForSingleObject(hOpMutex, INFINITE);
	bIPv4Enabled = state;
	if(hOpMutex) ReleaseMutex(hOpMutex);
}

void set_ipv6_enable(bool state)
{
	if(hOpMutex) WaitForSingleObject(hOpMutex, INFINITE);
	bIPv6Enabled = state;
	if(hOpMutex) ReleaseMutex(hOpMutex);
}
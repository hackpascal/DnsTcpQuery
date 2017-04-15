#include "stdafx.h"

void query_listen(void *data)
{
	SOCKET dns_sockfd;
	my_sockaddr dns_addr, from_addr;
	sockaddr_in6 tmp;
	my_addr dns4, dns6;
	char ipv6_addr[256];
	INT addrlen;

	int recvlen;
	char buff[1024];
	int fromlen;

	pthread_data tdata = (pthread_data)data;
	int size_of_sockaddr = tdata->Family == AF_INET ? sizeof sockaddr_in : sizeof sockaddr_in6;
	int ip_type = tdata->Family == AF_INET ? 4 : 6;

	dns_sockfd = socket(tdata->Family, SOCK_DGRAM, IPPROTO_UDP);
	if(dns_sockfd == INVALID_SOCKET)
	{
		PrintString(tdata->hMutex, "错误：创建 IPv%d socket 失败。WSALastError = %d\n", ip_type, WSAGetLastError());
		SetEvent(tdata->hStoppedEvent);
		return;
	}

	u_long uNonBlock = 1;
	ioctlsocket(dns_sockfd, FIONBIO, &uNonBlock);

	memset(&dns_addr, 0, sizeof my_sockaddr);
	if(tdata->Family == AF_INET)
	{
		dns_addr.addr.sin_family = AF_INET;
		dns_addr.addr.sin_addr.s_addr = inet_addr(lpListenAddr4);
		dns_addr.addr.sin_port = htons(53);
	}
	else
	{
		addrlen = sizeof(dns_addr.addr6);
		WSAStringToAddress(lpListenAddr6, AF_INET6, NULL, (sockaddr *) &dns_addr.addr6, &addrlen);
		dns_addr.addr6.sin6_family = AF_INET6;
//		inet_pton(AF_INET6, lpListenAddr6, &dns_addr.addr6.sin6_addr);
		dns_addr.addr6.sin6_port = htons(53);
		sprintf_s(ipv6_addr, sizeof(ipv6_addr), "[%s]", lpListenAddr6);
	}
	dns4.ipv4.s_addr = inet_addr(lpDNSAddr4);
//	inet_pton(AF_INET6, lpDNSAddr6, &dns6.ipv6);
	addrlen = sizeof(tmp);
	WSAStringToAddress(lpDNSAddr6, AF_INET6, NULL, (sockaddr *)&tmp, &addrlen);
	dns6.ipv6 = tmp.sin6_addr;

	if(bind(dns_sockfd, (const sockaddr *)&dns_addr, size_of_sockaddr) == SOCKET_ERROR)
	{
		PrintString(tdata->hMutex, "错误：绑定到 %s:53 失败。WSALastError = %d\n", tdata->Family == AF_INET ? lpListenAddr4 : ipv6_addr, WSAGetLastError());
		closesocket(dns_sockfd);
		SetEvent(tdata->hStoppedEvent);
		return;
	}

	PrintString(tdata->hMutex, "正在监听 %s:53 via UDP...\n", tdata->Family == AF_INET ? lpListenAddr4 : ipv6_addr);

	while(true)
	{
		if(WaitForSingleObject(tdata->hStopEvent, 50) != WAIT_TIMEOUT)
			break;

		fromlen = size_of_sockaddr;
		recvlen = recvfrom(dns_sockfd, buff, sizeof buff, 0, (sockaddr *)&from_addr, &fromlen);
		if(recvlen == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;

		if(recvlen > 0)
		{
			udp_peer *p = new udp_peer;
			char *attr;
			p->hMutexObj = tdata->hMutex;
			p->sockfd = dns_sockfd;
			p->peer = from_addr;
			p->peerlen = fromlen;
			p->data = new char[recvlen];
			memcpy_s(p->data, recvlen, buff, recvlen);
			p->datalen = recvlen;
			p->FamilyFrom = tdata->Family;

			attr = tdata->Family == AF_INET ? lpQueryAttr4 : lpQueryAttr6;
			if(attr[0] == '4')
			{
				p->Family = AF_INET;
				if(!ipv4_enabled())
					if(attr[1] == '6')
						p->Family = AF_INET6;
			}
			else
				if(attr[0] == '6')
				{
					p->Family = AF_INET6;
					if(!ipv6_enabled())
						if(attr[1] == '4')
							p->Family = AF_INET;
				}

			p->dns = p->Family == AF_INET ? dns4 : dns6;

			_beginthread(query_process, 0, (void *)p);
		}
	}

	closesocket(dns_sockfd);
	SetEvent(tdata->hStoppedEvent);

	PrintString(tdata->hMutex, "IPv%d 监听线程已结束\n", ip_type);
}

void query_process(void *data)
{
	SOCKET qr_sockfd;
	my_sockaddr qr_addr;
	struct timeval timeo = { 3, 0 };
	int sendlen;
	int recvlen;
	bool use_def_dns = true;
	
	udp_peer *p = (udp_peer *)data;
	memset(&qr_addr, 0, sizeof my_sockaddr);
	int size_of_sockaddr = p->Family == AF_INET ? sizeof sockaddr_in : sizeof sockaddr_in6;
	int ip_type = p->Family == AF_INET ? 4 : 6;

	unsigned char cached_dns_response[1536];
	int pkt_len, qtype;

	dns_pkt_t *pkt_hdr = (dns_pkt_t *) p->data;

	int family;
	char *domain = print_domain_request(p->data, &family);

	//检查缓存
	if (family && lookup_cache(domain, family == AF_INET ? 0 : 1) && ((ntohs(pkt_hdr->flags) & 0x7800) == 0))
	{
		memcpy(cached_dns_response, p->data, p->datalen);
		pkt_len = make_cached_dns_response(cached_dns_response, p->datalen, sizeof(cached_dns_response), &qtype);

		if (pkt_len < 0)
			goto _normal_path;

		sendto(p->sockfd, (char *) cached_dns_response, pkt_len, 0, (const sockaddr *)&p->peer, p->peerlen);

		PrintString(p->hMutexObj, "%s: 来自 IPv%d 的请求，查询 IPv%d 地址，使用缓存记录\n", domain, p->FamilyFrom == AF_INET ? 4 : 6, qtype == 0 ? 4 : 6);

		delete[] domain;
		delete[] p->data;
		delete p;

		return;
	}

_normal_path:
	//匹配规则
	int i = 0;
	for(i = 0;i < rules_count;i++)
	{
		if(!regexec(&rules[i].regex_comp, domain, 0, NULL, 0))
		{
			if(p->Family == AF_INET && rules[i].has_dns4)
			{
				use_def_dns = false;
				qr_addr.addr.sin_addr = rules[i].dnsaddr4;
				break;
			}
			if(p->Family == AF_INET6 && rules[i].has_dns6)
			{
				use_def_dns = false;
				qr_addr.addr6.sin6_addr = rules[i].dnsaddr6;
				break;
			}
			break;
		}
	}

	if (use_def_dns)
	{
		if (p->FamilyFrom != p->Family)
			PrintString(p->hMutexObj, "来自 IPv%d 的请求，查询 IPv%d 地址，转发到 IPv%d：%s\n", p->FamilyFrom == AF_INET ? 4 : 6, family == AF_INET ? 4 : 6, ip_type, domain);
		else
			PrintString(p->hMutexObj, "来自 IPv%d 的请求，查询 IPv%d 地址：%s\n", ip_type, family == AF_INET ? 4 : 6, domain);
	}
	else
	{
		char ip_addr[128];
		DWORD dwStrLen = sizeof (ip_addr);

		WSAAddressToString((sockaddr *)&qr_addr.addr, p->Family == AF_INET ? sizeof(qr_addr.addr) : sizeof(qr_addr.addr6), NULL, ip_addr, &dwStrLen);
//		inet_ntop(p->Family, p->Family == AF_INET ? (PVOID) &qr_addr.addr.sin_addr : (PVOID)&qr_addr.addr6.sin6_addr, ip_addr, 128);
		if (p->FamilyFrom != p->Family)
			PrintString(p->hMutexObj, "来自 IPv%d 的请求，查询 IPv%d 地址，转发到 IPv%d：%s, DNS: %s\n", p->FamilyFrom == AF_INET ? 4 : 6, family == AF_INET ? 4 : 6, ip_type, domain, ip_addr);
		else
			PrintString(p->hMutexObj, "来自 IPv%d 的请求，查询 IPv%d 地址：%s, DNS: %s\n", ip_type, family == AF_INET ? 4 : 6, domain, ip_addr);
	}
	
	delete [] domain;

	if (!proxy_af)
	{
	_normal_connect:
		qr_sockfd = socket(p->Family, SOCK_STREAM, IPPROTO_TCP);

		if (qr_sockfd == INVALID_SOCKET)
		{
			delete[] domain;
			delete[] p->data;
			delete p;
			return;
		}

		timeo.tv_sec = 5;
		setsockopt(qr_sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeo, sizeof(timeo));

		if (p->Family == AF_INET)
		{
			qr_addr.addr.sin_family = AF_INET;
			if (use_def_dns) qr_addr.addr.sin_addr = p->dns.ipv4;
			qr_addr.addr.sin_port = htons(53);
		}
		else
		{
			qr_addr.addr6.sin6_family = AF_INET6;
			if (use_def_dns) qr_addr.addr6.sin6_addr = p->dns.ipv6;
			qr_addr.addr6.sin6_port = htons(53);
		}

		if (connect(qr_sockfd, (const sockaddr *)&qr_addr, size_of_sockaddr) == SOCKET_ERROR)
		{
			delete[] p->data;
			delete p;
			closesocket(qr_sockfd);
			return;
		}
	}
	else
	{
		char recv_data[2], send_data[22];
		int len_to_send;
		unsigned short port;

		size_of_sockaddr = proxy_af == AF_INET ? sizeof sockaddr_in : sizeof sockaddr_in6;

		qr_sockfd = socket(proxy_af, SOCK_STREAM, IPPROTO_TCP);

		if (qr_sockfd == INVALID_SOCKET)
		{
			delete[] domain;
			delete[] p->data;
			delete p;
			return;
		}

		setsockopt(qr_sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeo, sizeof(timeo));

		if (connect(qr_sockfd, (const sockaddr *)&proxy_addr, size_of_sockaddr) == SOCKET_ERROR)
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

		sendlen = send(qr_sockfd, "\x05\x01\x00", 3, 0);

		if (sendlen != 3)
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

		recvlen = recv(qr_sockfd, recv_data, 2, 0);

		if (recvlen != 2)
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

		if (memcmp(recv_data, "\x05\x00", 2))
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

		port = htons(53);
		
		send_data[0] = 0x05;
		send_data[1] = 0x01;
		send_data[2] = 0x00;

		if (p->Family == AF_INET)
		{
			send_data[3] = 0x01;
			memcpy(&send_data[4], &p->dns.ipv4, 4);
			memcpy(&send_data[8], &port, 2);
			len_to_send = 10;
		}
		else
		{
			send_data[3] = 0x04;
			memcpy(&send_data[4], &p->dns.ipv6,16);
			memcpy(&send_data[20], &port, 2);
			len_to_send = 22;
		}

		sendlen = send(qr_sockfd, send_data, len_to_send, 0);

		if (sendlen != len_to_send)
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

		recvlen = recv(qr_sockfd, send_data, len_to_send, 0);

		if (recvlen != len_to_send)
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

		if (send_data[1] != 0)
		{
			closesocket(qr_sockfd);
			goto _normal_connect;
		}

	}

	u_short len = htons(p->datalen);

	char *databuf = new char[p->datalen + sizeof u_short];

	memcpy_s(databuf, p->datalen + sizeof u_short, &len, sizeof u_short);
	memcpy_s(databuf + sizeof u_short, p->datalen, p->data, p->datalen);

	sendlen = send(qr_sockfd, databuf, p->datalen + sizeof u_short, 0);

	delete [] databuf;

	if(sendlen == SOCKET_ERROR)
	{
		delete[] p->data;
		delete p;
		closesocket(qr_sockfd);
		return;
	}

	char buff[1024];

	recvlen = recv(qr_sockfd, buff, sizeof buff, 0);

	if(recvlen == SOCKET_ERROR)
	{
		delete[] p->data;
		delete p;
		closesocket(qr_sockfd);
		return;
	}

	if(recvlen)
	{
		sendto(p->sockfd, buff + 2, recvlen - 2, 0, (const sockaddr *)&p->peer, p->peerlen);
		if ((ntohs(pkt_hdr->flags) & 0x7800) == 0)
			dns_parse((unsigned char *) buff + 2, recvlen - 2, p->hMutexObj);
	}

	closesocket(qr_sockfd);
	delete[] p->data;
	delete p;
}

void PrintString(HANDLE hMutex, char *s, ...)
{
	int nSize;
	char *buff;
	va_list arglist;

	//线程同步
	if(hMutex) WaitForSingleObject(hMutex, INFINITE);

	va_start(arglist, s);

	//估算需要的缓冲区大小，不包含 NULL 终止符
	nSize = _vscprintf(s, arglist);
	//分配缓冲区，包含 NULL 字符
	buff = new char[nSize + 1];
	//调用格式化字符串的函数
	_vsprintf_s_l(buff, nSize + 1, s, NULL, arglist);
	//打印字符串
	printf(buff);
	//释放缓冲区
	delete [] buff;

	va_end(arglist);

	//释放
	if(hMutex) ReleaseMutex(hMutex);
}

char* print_domain_request(char *data, int *family)
{
	int i = 12;
	int l;
	unsigned short q_type;

	char *buff = new char[1024];
	memset(buff, 0, 1024);

	while(true)
	{
		l = data[i];
		if(l == 0) break;

		strncat_s(buff, 1024, data + i + 1, l);
		strcat_s(buff, 1024, ".");

		i += l + 1;
	}

	if (data[i] == 0)
	{
		i++;
		q_type = htons(*(unsigned short *)&data[i]);

		if (family)
		{
			if (q_type == 1)
				*family = AF_INET;
			else if (q_type == 28)
				*family = AF_INET6;
			else
				*family = 0;
		}
	}

	buff[strlen(buff) - 1] = 0;

	return buff;
}
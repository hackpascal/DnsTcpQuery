#include "stdafx.h"

char lpListenAddr4[256] = "127.0.0.1";
char lpListenAddr6[256] = "::1";

char lpDNSAddr4[256] = "8.8.8.8";
char lpDNSAddr6[256] = "2001:4860:4860::8888";

char lpQueryAttr4[10] = "46";
char lpQueryAttr6[10] = "64";

int strip_ipv4 = 0;
int strip_ipv6 = 0;

my_sockaddr proxy_addr;
int proxy_af = 0;

prules_record rules = NULL;
int rules_count = -1;

bool file_exists(char *path);

void read_param()
{
	char szPath[512];
	int pathlen = GetModuleFileName(0, szPath, 512);
	szPath[pathlen] = 0;

	char lpSocks5Addr[256] = "";
	unsigned short nSocksPort = 0;
	INT addrlen;

	int i = pathlen;
	while(i >= 0)
		if(szPath[--i] == '.') break;
	szPath[i + 1] = 0;
	strcat_s(szPath, 512, "ini");

	if(!file_exists(szPath)) return;

	char buff[256] = {};
	int lens;

	//指定监听地址
	lens = GetPrivateProfileString("Listen", "Addr4", "127.0.0.1", buff, 256, szPath);
	buff[lens] = 0;
	if (lens)
		memcpy_s(lpListenAddr4, 256, buff, lens + 1);

	lens = GetPrivateProfileString("Listen", "Addr6", "::1", buff, 256, szPath);
	buff[lens] = 0;
	if (lens)
		memcpy_s(lpListenAddr6, 256, buff, lens + 1);

	//指定 DNS 服务器
	lens = GetPrivateProfileString("General", "DNSAddr4", "8.8.8.8", buff, 256, szPath);
	buff[lens] = 0;
	if(lens)
		memcpy_s(lpDNSAddr4, 256, buff, lens + 1);
	
	lens = GetPrivateProfileString("General", "DNSAddr6", "2001:4860:4860::8888", buff, 256, szPath);
	buff[lens] = 0;
	if(lens)
		memcpy_s(lpDNSAddr6, 256, buff, lens + 1);

	//读取解析顺序
	lens = GetPrivateProfileString("Query", "From4", "44", buff, 10, szPath);
	buff[lens] = 0;
	if(lens)
		memcpy_s(lpQueryAttr4, 10, buff, lens + 1);

	lens = GetPrivateProfileString("Query", "From6", "64", buff, 10, szPath);
	buff[lens] = 0;
	if(lens)
		memcpy_s(lpQueryAttr6, 10, buff, lens + 1);

	//读取解析地址类型
	lens = GetPrivateProfileString("Query", "Strip4", "0", buff, 10, szPath);
	buff[lens] = 0;
	if (atoi(buff))
		strip_ipv4 = 1;

	lens = GetPrivateProfileString("Query", "Strip6", "0", buff, 10, szPath);
	buff[lens] = 0;
	if (atoi(buff))
		strip_ipv6 = 1;

	//读取代理信息
	lens = GetPrivateProfileString("Query", "ProxyAddr", "", buff, 10, szPath);
	buff[lens] = 0;
	if (lens)
		memcpy_s(lpSocks5Addr, 256, buff, lens + 1);

	lens = GetPrivateProfileString("Query", "ProxyPort", "0", buff, 10, szPath);
	buff[lens] = 0;
	nSocksPort = atoi(buff);

	if (!nSocksPort)
		lpSocks5Addr[0] = 0;
	else if (!lpSocks5Addr[0])
		nSocksPort = 0;

	if (lpSocks5Addr[0])
	{
		memset(&proxy_addr, 0, sizeof(proxy_addr));

		if (strchr(lpSocks5Addr, ':') == NULL)
		{
			addrlen = sizeof(proxy_addr.addr);
			if (!WSAStringToAddress(lpSocks5Addr, AF_INET, NULL, (sockaddr *)&proxy_addr.addr, &addrlen) /*inet_pton(AF_INET, lpSocks5Addr, (void *)&proxy_addr.addr.sin_addr)*/)
			{
				proxy_af = AF_INET;
				proxy_addr.addr.sin_family = AF_INET;
				proxy_addr.addr.sin_port = htons(nSocksPort);
			}
		}
		else
		{
			addrlen = sizeof(proxy_addr.addr6);
			if (!WSAStringToAddress(lpSocks5Addr, AF_INET6, NULL, (sockaddr *)&proxy_addr.addr6, &addrlen) /*inet_pton(AF_INET6, lpSocks5Addr, (void *)&proxy_addr.addr6.sin6_addr)*/)
			{
				proxy_af = AF_INET6;
				proxy_addr.addr6.sin6_family = AF_INET6;
				proxy_addr.addr6.sin6_port = htons(nSocksPort);
			}
		}
	}

	//读取DNS规则
	int quota = 1024;
	int cap = quota;
	char *rules_str = (char*)malloc(cap);
	lens = GetPrivateProfileString("Rules", NULL, NULL, rules_str, cap, szPath);
	while(lens + 2 >= cap)
	{
		cap += quota;
		rules_str = (char*)realloc(rules_str, cap);
		lens = GetPrivateProfileString("Rules", NULL, NULL, rules_str, cap, szPath);
	}

	rules_count = 0;
	if(lens)
	{
		
		int rules_num = 0;
		int i = 0;

		//统计项目数
		while(true)
		{
			if(rules_str[i])
				i++;
			else
			{
				rules_num++;
				if(rules_str[i + 1] == 0)
					break;
				i++;
			}
		}

		rules = new rules_record[rules_num];

		char *temp, *sp_ip, *sp_temp;
		char ipstr[255];
		sockaddr_in addr4;
		sockaddr_in6 addr6;
		bool has_addr4, has_addr6;
		int addr_len;
		regex_t reg;

		//分析每个项目
		i = 0;
		temp = rules_str;
		while(true)
		{
			memset(&reg, 0, sizeof reg);
			if(regcomp(&reg, temp, REG_EXTENDED | REG_ICASE))
				goto _next;

			ipstr[0] = 0;
			GetPrivateProfileString("Rules", temp, NULL, ipstr, 255, szPath);
			if(!strcmp(ipstr, ""))
				goto _next;

			has_addr4 = false;
			has_addr6 = false;

			sp_ip = ipstr;

			sp_temp = strchr(ipstr, '|');
			if(sp_temp) *sp_temp = 0;

			if(*sp_ip != 0)
			{
				addr_len = sizeof addr4;
				if(!WSAStringToAddress(sp_ip, AF_INET, NULL, (LPSOCKADDR)&addr4, &addr_len))
					has_addr4 = true;
			}

			
			if(sp_temp)
				sp_ip = sp_temp + 1;

			if(*sp_ip != 0)
			{
				addr_len = sizeof addr6;
				if(!WSAStringToAddress(sp_ip, AF_INET6, NULL, (LPSOCKADDR)&addr6, &addr_len))
					has_addr6 = true;
			}

			if(has_addr4 || has_addr6)
			{
				rules[i].regex_comp = reg;
				rules[i].dnsaddr4 = addr4.sin_addr;
				rules[i].dnsaddr6 = addr6.sin6_addr;
				rules[i].has_dns4 = has_addr4;
				rules[i].has_dns6 = has_addr6;
				i++;
			}

_next:
			temp += strlen(temp) + 1;
			if(*temp == 0) break;
		}

		rules_count = i;
		
	}

}

void clear_rules()
{
	for(int i = 0;i < rules_count;i++)
		regfree(&rules[i].regex_comp);
	delete [] rules;
}

bool file_exists(char *path)
{
	WIN32_FIND_DATA wfd;
	bool result = false;
	HANDLE hFind = FindFirstFile(path, &wfd);
	if (hFind != INVALID_HANDLE_VALUE && !(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		result = true; 
	}
	FindClose(hFind);
	return result;
}
#pragma once

#include <vector>

using std::vector;

typedef struct ip_record
{
	int type;
	union
	{
		unsigned char ipv4[4];
		unsigned char ipv6[16];
	};
	unsigned int ttl;
	DWORD cur_tick;
} ip_record;

typedef struct domain_record
{
	char domain[128];
	char cname[128];
	vector<ip_record> ips;
} domain_record;

struct dns_pkt_t
{
	unsigned short magic;
	unsigned short flags;
	unsigned short num_queries;
	unsigned short num_answers;
	unsigned short num_auth_rr;
	unsigned short num_extra_rr;
	unsigned char data[];
};

void init_cache_lock(void);
void delete_cache_lock(void);

void dns_parse(const unsigned char *buff, int len, HANDLE hPrintMutex);
int lookup_cache(const char *domain, int type);
int make_cached_dns_response(unsigned char *pkt, int len_origin, int len_total, int *qtype);
#include "stdafx.h"

vector<domain_record> domain_records;

HANDLE hCacheLock;

int find_ip_by_domain(vector<domain_record> &domains, const char *domain, vector<ip_record> &ips);

void init_cache_lock(void)
{
	hCacheLock = CreateMutex(NULL, FALSE, NULL);
}

void delete_cache_lock(void)
{
	CloseHandle(hCacheLock);
}

int add_record(const char* domain, unsigned char *ip, int type, DWORD ttl)
{
	ip_record iprec;
	domain_record domainrec;

	ttl = 3600;

	for (size_t i = 0; i < domain_records.size(); i++)
	{
		if (!_stricmp(domain_records[i].domain, domain))
		{
			for (size_t j = 0; j < domain_records[i].ips.size(); j++)
			{
				if (domain_records[i].ips[j].type == type)
				{
					if (!memcmp(domain_records[i].ips[j].ipv4, ip, type ? 16 : 4))
						return 0;
				}
			}

			iprec.type = type;
			iprec.cur_tick = GetTickCount() / 1000;
			iprec.ttl = ttl;
			memcpy(iprec.ipv6, ip, type ? 16 : 4);

			WaitForSingleObject(hCacheLock, INFINITE);
			domain_records[i].ips.push_back(iprec);
			ReleaseMutex(hCacheLock);

			return 1;
		}
	}

	iprec.type = type;
	iprec.cur_tick = GetTickCount() / 1000;
	iprec.ttl = ttl;
	memcpy(iprec.ipv6, ip, type ? 16 : 4);

	strcpy_s(domainrec.domain, sizeof(domainrec.domain), domain);
	domainrec.cname[0] = 0;
	domainrec.ips.push_back(iprec);

	WaitForSingleObject(hCacheLock, INFINITE);
	domain_records.push_back(domainrec);
	WaitForSingleObject(hCacheLock, INFINITE);

	return 1;
}

int dns_parse_name(const unsigned char *head, const unsigned  char *ptr, const unsigned char **end, char *value)
{
	unsigned int offset;
	const unsigned char *pend;
	int len, total_len = 0;

	while (true)
	{
		if ((*ptr & 0xc0) == 0xc0)
		{
			offset = *(unsigned short *)ptr;
			ptr += 2;
			offset = ntohs(offset);
			offset &= 0x3fff;

			if ((size_t)(ptr - head) - 2 == offset)
			{
				value[0] = 0;
				total_len = 0;
				break;
			}

			len = dns_parse_name(head, head + offset, &pend, value);
			if (len < 0)
				return len;

			total_len += len;

			break;
		}

		len = *(unsigned char *)ptr;
		ptr++;

		memcpy(value, ptr, len);
		value += len;
		*value = '.';

		ptr += len;
		total_len += len;

		if (!*ptr)
		{
			*value = 0;
			ptr++;
			break;
		}
		else
		{
			total_len++;
			value++;
		}
	}

	if (end)
		*end = ptr;

	return total_len;
}

void dns_parse(const unsigned char *buff, int len, HANDLE hPrintMutex)
{
	unsigned short num_queries;
	unsigned short num_answers;
	unsigned short q_type, q_class;
	unsigned short a_type, a_class;
	unsigned int a_ttl;
	unsigned short a_len;
	const unsigned char *ptr;
	char name[128];
	int add = 0, skip = 0;
	vector<domain_record> tmp_domain_records;
	domain_record tmp_domain;
	ip_record tmp_ip;

	dns_pkt_t *pkt = (dns_pkt_t *)buff;

	num_queries = ntohs(pkt->num_queries);
	num_answers = ntohs(pkt->num_answers);

	if (!num_answers)
		return;

	ptr = pkt->data;

	while (num_queries)
	{
		dns_parse_name(buff, ptr, &ptr, name);
		q_type = htons(*(unsigned short *)ptr);
		ptr += 2;
		q_class = htons(*(unsigned short *)ptr);
		ptr += 2;

		num_queries--;
	}

	while (num_answers)
	{
		add = 0;
		skip = 0;
		tmp_domain.ips.clear();
		if (!dns_parse_name(buff, ptr, &ptr, name))
			skip = 1;
		strcpy_s(tmp_domain.domain, sizeof (tmp_domain.domain), name);
		a_type = htons(*(unsigned short *)ptr);
		ptr += 2;
		a_class = htons(*(unsigned short *)ptr);
		ptr += 2;
		a_ttl = htonl(*(unsigned int *)ptr);
		ptr += 4;
		a_len = htons(*(unsigned short *)ptr);
		ptr += 2;

		tmp_domain.cname[0] = 0;

		if (a_type == 5)
		{
			dns_parse_name(buff, ptr, &ptr, name);
			strcpy_s(tmp_domain.cname, sizeof (tmp_domain.domain), name);
			add = 1;
		}
		else if (a_type == 1)
		{
			memset(&tmp_ip, 0, sizeof(tmp_ip));
			tmp_ip.type = 0;
			memcpy(tmp_ip.ipv4, ptr, 4);
			tmp_ip.ttl = a_ttl;
			ptr += 4;
			add = 1;
			tmp_domain.ips.push_back(tmp_ip);
		}
		else if (a_type == 28)
		{
			memset(&tmp_ip, 0, sizeof(tmp_ip));
			tmp_ip.type = 1;
			memcpy(tmp_ip.ipv6, ptr, 16);
			tmp_ip.ttl = a_ttl;
			ptr += 16;
			add = 1;
			tmp_domain.ips.push_back(tmp_ip);
		}
		else
		{
			ptr += a_len;
			add = 0;
		}

		if (add && !skip)
		{
			tmp_domain_records.push_back(tmp_domain);
		}

		num_answers--;
	}

	for (size_t i = 0; i < tmp_domain_records.size(); i++)
	{
		if (tmp_domain_records[i].ips.size())
			continue;

		if (!tmp_domain_records[i].cname[0])
			continue;

		find_ip_by_domain(tmp_domain_records, tmp_domain_records[i].cname, tmp_domain_records[i].ips);
	}

	for (size_t i = 0; i < tmp_domain_records.size(); i++)
	{
		for (size_t j = 0; j < tmp_domain_records[i].ips.size(); j++)
			if (add_record(tmp_domain_records[i].domain, tmp_domain_records[i].ips[j].ipv4,
				tmp_domain_records[i].ips[j].type, tmp_domain_records[i].ips[j].ttl))
			{
				void PrintString(HANDLE hMutex, char *s, ...);
				if (tmp_domain_records[i].ips[j].type == 0)
				{
					PrintString(hPrintMutex, "Ìí¼Ó»º´æ¼ÇÂ¼£º %s <==> %u.%u.%u.%u\n", tmp_domain_records[i].domain,
						tmp_domain_records[i].ips[j].ipv4[0] & 0xff, tmp_domain_records[i].ips[j].ipv4[1] & 0xff,
						tmp_domain_records[i].ips[j].ipv4[2] & 0xff, tmp_domain_records[i].ips[j].ipv4[3] & 0xff);
				}
				else
				{
					char buff[256];
					sockaddr_in6 tmp;
					DWORD dwStrLen = sizeof(buff);

					memcpy(&tmp.sin6_addr, tmp_domain_records[i].ips[j].ipv6, 16);
					tmp.sin6_family = AF_INET6;
					tmp.sin6_port = 0;

					WSAAddressToString((sockaddr *)&tmp, AF_INET6, NULL, buff, &dwStrLen);
//					inet_ntop(AF_INET6, tmp_domain_records[i].ips[j].ipv6, buff, sizeof(buff));
					PrintString(hPrintMutex, "Ìí¼Ó»º´æ¼ÇÂ¼£º %s <==> %s\n", tmp_domain_records[i].domain, buff);

				}
			}
	}
}

int ip_exists(vector<ip_record> &ips, unsigned char *ip, int type)
{
	for (size_t i = 0; i < ips.size(); i++)
	{
		if (ips[i].type != type)
			continue;

		if (!memcmp(ips[i].ipv6, ip, type ? 16 : 4))
			return 1;
	}

	return 0;
}

int find_ip_by_domain(vector<domain_record> &domains, const char *domain, vector<ip_record> &ips)
{
	int success = 0;

	for (size_t i = 0; i < domains.size(); i++)
	{
		if (!_stricmp(domains[i].domain, domain))
		{
			if (!domains[i].ips.size())
				if (domains[i].cname[0])
					find_ip_by_domain(domains, domains[i].cname, domains[i].ips);

			if (domains[i].ips.size())
			{
				if (!ips.size())
				{
					ips = domains[i].ips;
					success = 1;
				}
				else
				{
					for (size_t j = 0; j < domains[i].ips.size(); j++)
					{
						if (ip_exists(ips, domains[i].ips[j].ipv6, domains[i].ips[j].type))
							continue;

						ips.push_back(domains[i].ips[j]);
						success = 1;
					}
				}
			}
		}
	}

	return success;
}

int lookup_cache(const char *domain, int type)
{
	int num = 0;

	WaitForSingleObject(hCacheLock, INFINITE);

	for (size_t i = 0; i < domain_records.size(); i++)
	{
		if (!_stricmp(domain_records[i].domain, domain))
		{
			for (vector<ip_record>::iterator it = domain_records[i].ips.begin(); it != domain_records[i].ips.end(); )
			{
				if (it->ttl < (GetTickCount() / 1000 - it->cur_tick))
					it = domain_records[i].ips.erase(it);
				else
					it++;
			}

			for (size_t j = 0; j < domain_records[i].ips.size(); j++)
			{
				if (domain_records[i].ips[j].type == type)
					num++;
			}

			break;
		}
	}

	ReleaseMutex(hCacheLock);

	return num;
}

int make_cached_dns_response(unsigned char *pkt, int len_origin, int len_total, int *qtype)
{
	dns_pkt_t *pkt_hdr = (dns_pkt_t *) pkt;
	unsigned char *ptr = pkt + len_origin;
	unsigned short flags;
	const unsigned char *ptr_qdata;
	unsigned short num_queries, num_answers = 0;
	unsigned short q_type, q_class;
	char name[128], domain[128];
	int type = -1;

	num_queries = ntohs(pkt_hdr->num_queries);

	if (!num_queries)
		return -1;

	ptr_qdata = pkt_hdr->data;

	while (num_queries)
	{
		dns_parse_name(pkt, ptr_qdata, &ptr_qdata, name);
		q_type = htons(*(unsigned short *)ptr_qdata);
		ptr_qdata += 2;
		q_class = htons(*(unsigned short *)ptr_qdata);
		ptr_qdata += 2;

		if (q_type == 1)
		{
			if (!strip_ipv4)
			{
				if (type < 0)
				{
					type = 0;
					memcpy(domain, name, sizeof(domain));
				}
			}
		}
		else if (q_type == 28)
		{
			if (!strip_ipv6)
			{
				if (type < 0)
				{
					type = 1;
					memcpy(domain, name, sizeof(domain));
				}
			}
		}

		num_queries--;
	}

	if (type < 0)
	{
		flags = ntohs(pkt_hdr->flags);
		flags |= 5;
		pkt_hdr->flags = htons(flags);

		return len_origin;
	}

	flags = ntohs(pkt_hdr->flags);

	flags |= 0x8000;

	if (flags & 0x0100)
		flags |= 0x0080;

	pkt_hdr->flags = htons(flags);

	WaitForSingleObject(hCacheLock, INFINITE);

	for (size_t i = 0; i < domain_records.size(); i++)
	{
		if (!_stricmp(domain_records[i].domain, domain))
		{
			for (size_t j = 0; j < domain_records[i].ips.size(); j++)
			{
				if (domain_records[i].ips[j].type == type)
				{
					if (len_total - len_origin < 16)
						break;

					*(unsigned short *)ptr = htons(0xc00c);
					ptr += 2;

					*(unsigned short *)ptr = htons(type == 0 ? 1 : 28);
					ptr += 2;

					*(unsigned short *)ptr = htons(1);
					ptr += 2;

					*(unsigned int *)ptr = htonl(domain_records[i].ips[j].cur_tick / 1000 + domain_records[i].ips[j].ttl - GetTickCount() / 1000);
					ptr += 4;

					*(unsigned short *)ptr = htons(type == 0 ? 4 : 16);
					ptr += 2;

					memcpy(ptr, domain_records[i].ips[j].ipv6, type == 0 ? 4 : 16);
					ptr += (type == 0 ? 4 : 16);

					len_origin += 12 + (type == 0 ? 4 : 16);
					num_answers++;
				}
			}

			break;
		}
	}

	ReleaseMutex(hCacheLock);

	pkt_hdr->num_answers = htons(num_answers);

	if (qtype)
		*qtype = type;

	return len_origin;
}
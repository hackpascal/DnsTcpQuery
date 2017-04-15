typedef struct
{
	regex_t regex_comp;
	in_addr dnsaddr4;
	in6_addr dnsaddr6;
	bool has_dns4;
	bool has_dns6;
} rules_record, *prules_record;

extern prules_record rules;
extern int rules_count;

extern char lpListenAddr4[256];
extern char lpListenAddr6[256];

extern char lpDNSAddr4[256];
extern char lpDNSAddr6[256];

extern char lpQueryAttr4[10];
extern char lpQueryAttr6[10];

extern char lpTestAddr4[256];
extern char lpTestAddr6[256];

extern int strip_ipv4;
extern int strip_ipv6;

extern my_sockaddr proxy_addr;
extern int proxy_af;

void read_param();
void clear_rules();
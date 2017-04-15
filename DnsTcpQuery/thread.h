typedef union
{
	sockaddr_in addr;
	sockaddr_in6 addr6;
} my_sockaddr;

typedef union
{
	in_addr ipv4;
	in6_addr ipv6;
} my_addr;

typedef struct
{
	int Family;
	int FamilyFrom;
	HANDLE hMutexObj;
	SOCKET sockfd;
	my_sockaddr peer;
	my_addr dns;
	int peerlen;
	char *data;
	int datalen;
} udp_peer;

typedef struct
{
	int Family;
	HANDLE hStopEvent;
	HANDLE hStoppedEvent;
	HANDLE hMutex;
} thread_data, *pthread_data;

void query_listen(void *data);
void query_process(void *data);


void PrintString(HANDLE hMutex, char *s, ...);
char* print_domain_request(char *data, int *family);
#include <time.h>

struct usrinfoSet {
	char *usr;
	char *pw;
	char dev[0xc];
	char ip[0x10];
	char mac[0x8];
};

struct mediate {
	char serverType[0xc];
	char host[0x10];
	char randnum[0x20];
	char *programName;
	char filePath[0xff];
	time_t onTime;
};

struct infoset  {
	struct sockaddr_in * psv;
	struct usrinfoSet * pui;
	struct mediate *pmt;
};

void sendRequestPacket(int sockfd, struct infoset * pinfo, int mode, int ttor);

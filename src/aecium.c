#include <stdio.h>		//for perror
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <arpa/inet.h>  //for inet_ntoa
#include <net/if.h>
#include <unistd.h>
#include <errno.h>
#include <iconv.h>
#include <locale.h>
#include "md5.h"
#include "aecium.h"
#define PORT 3848 /* Server Port */

static char *programMode;
static char version[0x8] = "0.0.1";

void usage(int status)
{
	if ( status != EXIT_SUCCESS) {
		fprintf(stderr, "Try \'%s -h\' for more information.\n", programMode);
	} else {

		printf("Usage 1: %s [-h Host] -u Username -p Password [-d Device] [-f]\n", programMode);
		puts("\t-h Host\t\t\tattestation host IP address.");
		puts("\t-u Username\t\tyour user name.");
		puts("\t-p Password\t\tyour user password.");
		puts("\t-d Device\t\tyour network card interface.");
		puts("\t-f\t\t\tfind server type.");

		printf("\nUsage 2: %s -l\n", programMode);
		puts("\t-l Leave\t\t\tleave Internet.");

		printf("\nUsage 3: %s -v\n", programMode);
		puts("\t-v Version\t\tshow program version.");
	}

	exit(status);
}

void getPath(struct mediate *pmt)
{
	char **programName = &(pmt -> programName);
	char *filePath = pmt -> filePath;

	if ( programMode ) {
		*programName = strrchr(programMode, '/');
		if ( *programName ) {
			++ *programName;
		} else {
			*programName = programMode;
		}
	}

	if ( *programName ) {
		strcpy(filePath, getenv("HOME"));
		strcat(filePath, "/.");
		strcat(filePath, *programName);
	}	
}

int getOtherPid(char *programName)
{
	FILE *fd;
	int len = strlen(programName) + 0x10;
	int pid = 0;
	char command[len];

	strcpy(command, "ps -A c | grep ");
	strcat(command, programName);

	if ( (fd = popen(command, "r")) == NULL ) {
		perror("popen");
		exit(EXIT_FAILURE);
	}

	for( char buf[0x50] = {0x0}; fgets(buf, 0x50, fd) && pid == 0x0; ) {
		if ( strstr(buf, programName) ) {
			if ( getpid() == (pid = atoi(buf)) ) {
				pid = 0x0;
			}
		}
	}

	pclose(fd);

	return pid;
}

void checkArgument(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	if ( argc == 0x2 ) {
		char *s = argv[0x1];

		if ( !strcmp(s, "-l") ) {
			return;
		} else if ( !strcmp(s, "-h") ) {
			usage(EXIT_SUCCESS);
		} else if ( !strcmp(s, "-v") ) {
			printf("Version: %s\n", version);
			exit(EXIT_SUCCESS);
		} else {
			usage(EXIT_FAILURE);
		}
	} else if ( argc < 5 || argc > 0xa ) {
		usage(EXIT_FAILURE);
	}

	// access Internet argument.
	for (int i = 0x1; i < argc;) {
		int tmp = 0x2;
		char *s = argv[i];

		if ( i == argc - 1 ) {
			if ( strcmp(s, "-f") == 0 ) {
				strcpy(pmt -> serverType, "aecium");
				tmp = 1;
			} else {
				usage(EXIT_FAILURE);
			}
		} else if ( strcmp(s, "-h") == 0x0 ) {
			memcpy(pmt -> host, argv[i + 1], strlen(argv[i + 1]));
		} else if ( strcmp(s, "-u") == 0x0 ) {
			pui -> usr = argv[i + 1];
		} else if ( strcmp(s, "-p") == 0x0 ) {
			pui -> pw = argv[i + 1];
		} else if ( strcmp(s, "-d") == 0x0 ) {
			memcpy(pui -> dev, argv[i + 1], strlen(argv[i + 1]));
		} else if ( strcmp(s, "-f") == 0x0 ) {
			strcpy(pmt -> serverType, "aecium");
			tmp = 1;
		} else {
			usage(EXIT_FAILURE);
		}

		i += tmp;
	}

}

void infoFromFile(struct infoset * const pinfo)
{
		struct usrinfoSet *pui = pinfo -> pui;
		struct mediate *pmt = pinfo -> pmt;
		time_t *onTime = &(pmt -> onTime);
		unsigned int hostlen = strlen(pmt -> host), devlen = strlen(pui -> dev), randnumlen = strlen(pmt -> randnum), stlen = strlen(pmt -> serverType);
		FILE *fd;

		if ( (fd = fopen(pmt -> filePath, "r")) == NULL ) {
			printf("fopen(%s, \"r\"): %s\n", pmt -> filePath, strerror(errno));
			usage(EXIT_FAILURE);
		}

		for ( char buf[0x50] = {0x0}; fgets(buf, 0x50, fd); ) {

			if ( buf[strlen(buf) - 1] == '\n' ) {
				buf[strlen(buf) - 1] = '\0';
			}

			if ( strstr(buf, "interface=") ) {
				if ( devlen == 0x0 ) {
					strcpy(pui -> dev, buf + 0xa);
					devlen = strlen(pui -> dev);
				}
			} else if ( strstr(buf, "host=") ) {
				if ( hostlen == 0x0 ) {
					strcpy(pmt -> host, buf + 0x5);
					hostlen = strlen(pmt -> host);
				}
			} else if ( strstr(buf, "server=") ) {
				if ( stlen == 0x0 ) {
					strcpy(pmt -> serverType, buf + 0x7);
					stlen = strlen(pmt -> serverType);
				}
			} else if ( strstr(buf, "randnum=") ) {
				if ( randnumlen == 0x0 ) {
					strcpy(pmt -> randnum, buf + 0x8);
					randnumlen = strlen(pmt -> randnum);
				}
			} else if ( strstr(buf, "time=") ) {
				if ( *onTime == 0x0 ) {
					*onTime = (time_t)atol(buf + 0x5);
				}
			}

		}

		fclose(fd);
}

void getInfo(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	checkArgument(argc, argv, pinfo);

	// When leave, strlen(pmt -> host) absolutely equal zero.
	if ( !strlen(pmt -> host) || !strlen(pui -> dev) || !strlen(pmt -> serverType) ) {
		infoFromFile(pinfo);
	}

	// When argc equal 0x2, 
	if ( strcmp(pmt -> serverType, "aecium") == 0 ) {//&& argc != 0x2 ) {
		char c = 0x0;

		memset(pmt -> serverType, 0x0, sizeof(pmt -> serverType));

		puts("Select service:");
		puts("\t1. int");
		fprintf(stdout, "please select(type \'e\' to exit):");

		if ( (c = getchar()) == 'e' ) {
			exit(EXIT_SUCCESS);
		} else if ( c == '1' ) {
			strcpy(pmt -> serverType, "int");
		} else {
			fprintf(stderr, "Invalid service!\n");
			exit(EXIT_FAILURE);
		}
	}

	if ( argc == 0x2 ) {
		if ( !( strlen(pmt -> randnum) && strlen(pmt -> host) && strlen(pui -> dev) ) ) {
			fprintf(stderr, "Reading random number, host, or network card interface fails, check the file \"%s\".\n", pmt -> filePath);
			exit(EXIT_FAILURE);
		}
	} else {
		memset(pmt -> randnum, 0x0, sizeof(pmt -> randnum));
		pmt -> onTime = 0x0;

		if ( !( pui -> usr && pui -> pw ) ) {
			fprintf(stderr, "Please input username and password!\n");
			usage(EXIT_FAILURE);
		}

		if ( !( strlen(pmt -> host) && strlen(pmt -> serverType) && strlen(pui -> dev) ) ) {
			fprintf(stderr, "Reading host, network card interface, server type fails, check the file \"%s\".\n", pmt -> filePath);
			usage(EXIT_FAILURE);
		}
	}

}

void serverInit(struct infoset * const pinfo)
{
	struct sockaddr_in *psv = pinfo -> psv;
	struct mediate *pmt = pinfo -> pmt;

	memset(psv, 0x0, sizeof(struct sockaddr_in));

	psv -> sin_family = AF_INET;
	psv -> sin_port = htons(PORT);
	psv -> sin_addr.s_addr = inet_addr(pmt -> host);
}

void infoInit(int argc, char **argv, struct infoset * const pinfo)
{
	struct mediate *pmt = pinfo -> pmt;

	programMode = argv[0];

	getPath(pmt);
	getInfo(argc, argv, pinfo);

}

void getAddr(int sockfd, struct usrinfoSet * pui)
{
	struct ifreq addr;
	
	memset(&addr, 0x0, sizeof addr);
	strcpy(addr.ifr_name, pui -> dev);
	
	if (ioctl(sockfd, SIOCGIFADDR, (char *)&addr) == -1) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	strcpy(pui -> ip, inet_ntoa(((struct sockaddr_in *)&addr.ifr_addr) -> sin_addr));

	memset(&addr, 0, sizeof addr);
	strcpy(addr.ifr_name, (*pui).dev);

	if(ioctl(sockfd, SIOCGIFHWADDR, (char *)&addr) == -1) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	memcpy(pui -> mac, addr.ifr_hwaddr.sa_data, 0x6);
}

void chief(struct infoset * pinfo, int accessOrLeave)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	getAddr(sockfd, pinfo -> pui);

	if ( accessOrLeave ) {
		sendRequestPacket(sockfd, pinfo, 0x1, 0x3);
	} else {
		sendRequestPacket(sockfd, pinfo, 0x5, 0x3);
	}

	close(sockfd);
}

void start(int accessOrLeave, struct infoset * pinfo)
{
	int other_pid = getOtherPid(pinfo -> pmt -> programName);

	if ( other_pid ) {
		if ( accessOrLeave ) {
			fprintf(stderr, "You have already accessed Internet yet!\n");
			exit(EXIT_FAILURE);
		} else {
			if ( kill(other_pid, SIGKILL) == -1 ) {
				perror("kill");
				exit(EXIT_FAILURE);
			} else {
				chief(pinfo, accessOrLeave);
			}
		}
	} else {
		if ( accessOrLeave ) {
			chief(pinfo, accessOrLeave);
		} else {
			fprintf(stderr, "The procedure had not already run!\n");
			exit(EXIT_FAILURE);
		}
	}
}

void aecium(int argc, char **argv)
{
	struct usrinfoSet usrinfo;
	struct sockaddr_in server_addr;
	struct mediate mtinfo;
	struct infoset info;

	info.pui = &usrinfo;
	info.psv = &server_addr;
	info.pmt = &mtinfo;

	memset(&usrinfo, 0x0, sizeof(struct usrinfoSet));
	memset(&mtinfo, 0x0, sizeof(struct mediate));

	infoInit(argc, argv, &info);
	serverInit(&info);

	// Zero represent leaving, and nonzero accessing.
	start(argc == 0x2 ? 0x0 : 0x1, &info);
}

bool pkgEncrypt(char *s, int len)
{
	if (s == NULL || len <= 0)
		return false;

	for (int i = 0; i < len; i++) {
		char c, tmp, dest;
		c = s[i];
		dest = (c & 0x1) << 7;

		tmp = (c & 0x2) >> 1;
		dest = tmp | dest;

		tmp = (c & 0x4) << 2;
		dest = tmp | dest;

		tmp = (c & 0x8) << 2;
		dest = tmp | dest;

		tmp = (c & 0x10) << 2;
		dest = tmp | dest;

		tmp = (c & 0x20) >> 2;
		dest = tmp | dest;

		tmp = (c & 0x40) >> 4;
		dest = tmp | dest;

		tmp = (c & 0x80) >> 6;
		dest = tmp | dest;

		s[i] = dest;
	}

	return true;
}

bool pkgDecrypt(char *s, int len)
{
	if (s == NULL || len <= 0)
		return false;

	for (int i = 0; i < len; i++) {
		char c, tmp ,dest;

		c = s[i];

		dest = (c & 0x1) << 1;

		tmp = (c & 0x2) << 6;
		dest = tmp | dest;

		tmp = (c & 0x4) << 4;
		dest = tmp | dest;

		tmp = (c & 0x8) << 2;
		dest = tmp | dest;

		tmp = (c & 0x10) >> 2;
		dest = tmp | dest;

		tmp = (c & 0x20) >> 2;
		dest = tmp | dest;

		tmp = (c & 0x40) >> 2;
		dest = tmp | dest;

		tmp = (c & 0x80) >> 7;
		dest = tmp | dest;

		s[i] = dest;
	}

	return true;
}

void sendGeneralPacket(int sockfd, const struct infoset *pinfo, int mode)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	char *pkg;
	char *ppkg;

	if ( mode == 0x1 ) {
		int usrlen = strlen(pui -> usr), pwlen = strlen(pui -> pw), iplen = strlen(pui -> ip), maclen = 0x6, stlen = strlen(pmt -> serverType);
		int sendbytes = usrlen + pwlen + iplen + maclen + stlen + 0x1c;

		pkg = (char *)calloc(sendbytes, sizeof(char));
		ppkg = pkg;

		*ppkg++ = mode;
		*ppkg++ = sendbytes;
		ppkg += 0x10;

		*ppkg++ = 0x1;
		*ppkg++ = usrlen + 0x2;
		memcpy(ppkg, pui -> usr, usrlen);
		ppkg += usrlen;

		*ppkg++ = 0x2;
		*ppkg++ = pwlen + 0x2;
		memcpy(ppkg, pui -> pw, pwlen);
		ppkg += pwlen;

		*ppkg++ = 0x7;
		*ppkg++ = maclen + 0x2;
		memcpy(ppkg, pui -> mac, maclen);
		ppkg += maclen;

		*ppkg++ = 0x9;
		*ppkg++ = iplen + 0x2;
		memcpy(ppkg, pui -> ip, iplen);
		ppkg += iplen;

		*ppkg++ = 0xa;
		*ppkg++ = stlen + 0x2;
		memcpy(ppkg, pmt -> serverType, stlen);
		ppkg += stlen;
	} else if ( mode == 0x3 || mode ==0x5 ) {
		int maclen = 0x6, iplen = strlen(pui -> ip), randnumlen = strlen(pmt -> randnum);
		int sendbytes = maclen + iplen + randnumlen + 0x18;

		pkg = calloc(sendbytes, sizeof(char));
		ppkg = pkg;

		*ppkg++ = mode;
		*ppkg++ = sendbytes;
		ppkg += 0x10;

		*ppkg++ = 0x7;
		*ppkg++ = maclen + 2;
		memcpy(ppkg, pui -> mac, maclen);
		ppkg += maclen;

		*ppkg++ = 0x8;
		*ppkg++ = randnumlen + 2;
		memcpy(ppkg, pmt -> randnum, randnumlen);
		ppkg += randnumlen;

		*ppkg++ = 0x9;
		*ppkg++ = iplen + 2;
		memcpy(ppkg, pui -> ip, iplen);
		ppkg += iplen;
	} else if ( mode == 0x7 ) {
		int maclen = 0x6;
		int sendbytes = maclen + 0x14;

		pkg = (char *)calloc(sendbytes, sizeof(char));
		ppkg = pkg;

		*ppkg++ = mode;
		*ppkg++ = sendbytes;
		ppkg += 0x10;

		*ppkg++ = 0x7;
		*ppkg++ = maclen + 0x2;
		memcpy(ppkg, pui -> mac, maclen);
		ppkg += maclen;
	} else {
		fprintf(stderr, "Invalid structure!\n");
		exit(EXIT_FAILURE);
	}

	MD5Calc(pkg + 2, pkg, pkg[0x1]);
	pkgEncrypt(pkg, pkg[0x1]);

	if ( sendto(sockfd, pkg, (size_t)(ppkg - pkg), 0, (struct sockaddr *)(pinfo -> psv), sizeof (struct sockaddr)) == -1 ) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}

	free(pkg);
}

void sendAccessPacket(int sockfd, const struct infoset * pinfo)
{
	sendGeneralPacket(sockfd, pinfo, 0x1);
}

void sendKeepPacket(int sockfd, const struct infoset * pinfo)
{
	sendGeneralPacket(sockfd, pinfo, 0x3);
}

void sendLeavePacket(int sockfd, const struct infoset * pinfo)
{
	sendGeneralPacket(sockfd, pinfo, 0x5);
}

void sendServicePacket(int sockfd, const struct infoset * pinfo)
{
	sendGeneralPacket(sockfd, pinfo, 0x7);
}

void sendRequestMode(int sockfd, const struct infoset * pinfo, int mode)
{
	if ( mode == 0x1 ) {
		sendAccessPacket(sockfd, pinfo);
	} else if ( mode == 0x3 ) {
		sendKeepPacket(sockfd, pinfo);
	} else if ( mode == 0x5 ) {
		sendLeavePacket(sockfd, pinfo);
	} else if ( mode == 0x7 ) {
		sendServicePacket(sockfd, pinfo);
	} else {
		exit(EXIT_FAILURE);
	}
}

void gbToUTF8(char *src)
{
	char dest[0x80] = {0x0};
	char *pdest = dest;
	char *psrc = src;
	size_t destsize = sizeof(dest);
	size_t srclen = strlen(src);
	iconv_t cd;

	if ( (iconv_t)-1 != (cd = iconv_open("UTF-8", "GB18030")) ) {
		int convNum = iconv(cd, &psrc, &srclen, &pdest, &destsize);

		if ( convNum == -1 ) {
			perror("iconv");
			exit(EXIT_FAILURE);
		} else {
			if ( strlen(dest) ) {
				strcpy(src, dest);
			}
		}
	} else {
		perror("iconv_open");
		exit(EXIT_FAILURE);
	}
}

void checkPacket(char * pkg, int pkgsize)
{
	char md5[0x10] = {0x0};
	int pkglen = pkg[1];
	int md5len = 0x10;

	if ( pkglen <= pkgsize && pkglen > 0x11) {
		memcpy(md5, pkg + 0x2, md5len);
		memset(pkg + 0x2, 0x0, md5len);

		MD5Calc(pkg + 0x2, pkg, pkglen);

		if ( memcmp(md5, pkg + 0x2, md5len) ) {
			fprintf(stderr, "Check MD5 fail!\n");
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "Invalid package size!\n");
		exit(EXIT_FAILURE);
	}
}

void analyzePacket(const char * pkg, char * const randnum, int mode)
{
	char msg[0x100] = {0x0};
	char err[0x3c] = {0x0};
	int sorf = 0x0;

	if ( pkg[0] > 0x9 ) {
		exit(EXIT_SUCCESS);
	}

	pkg += 0x14;
	sorf = *pkg;

	if ( sorf == 0x0 || ( sorf== 0x1 && mode == 0x1 ) ) {
		pkg += *(pkg - 1) - 0x2;
		if ( *pkg == 0x8 ) {
			++ pkg;

			if ( sorf == 0x1 ) {
				if ( *pkg <= 0x20 ) {
					memcpy(randnum, pkg + 1, *pkg);
				} else {
					snprintf(err, 0x3c, "Invalid package, or packet mode has been changed!");
				}
			}

			pkg += *pkg + 1;

			if ( sorf == 0x1 ) {
				pkg += 0x6;
			}

			if ( *pkg == 0xb ) {
				++ pkg;
				memcpy(msg, pkg + 1, *pkg);
			} else {
				snprintf(err, 0x3c, "Invalid package, or packet mode has been changed!");
			}
		} else {
			snprintf(err, 0x3c, "Invalid package, or packet mode has been changed!");
		}
	}

	if ( strlen(msg) ) {
		char curLocale[0x20] = {0x0};
		char *envLocale;

		strcpy(curLocale, setlocale(LC_CTYPE, NULL));
		envLocale = setlocale(LC_CTYPE, "");

		if ( strstr(envLocale, "UTF-8") || strstr(envLocale, "utf8") ) {
			gbToUTF8(msg);
		}

		setlocale(LC_CTYPE, curLocale);

		puts(msg);

		if ( sorf == 0x0 ) {
			exit(EXIT_SUCCESS);
		}
	}

	if ( strlen(err) ) {
		puts(err);
		exit(EXIT_FAILURE);
	}
}

void handlePacket(char * const pkg, int pkgsize, int sockfd, struct infoset * pinfo, int mode)
{
	struct usrinfoSet *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	pkgDecrypt(pkg, pkgsize);
	checkPacket(pkg, pkgsize);
	analyzePacket(pkg, pmt -> randnum, mode);

	if ( pkg[0] != mode + 0x1 ) {
		puts("Invalid package, or packet mode has been changed!");
		exit(EXIT_FAILURE);
	}

	if ( mode == 0x1 ) {
		FILE *fd;
		int pid;

		free(pkg);// When mode equal 0x1(access Internet), free pkg here.

		puts("The authentication succeeded, and now you can access Internet!");

		if ( fd = fopen(pmt -> filePath, "w") ) {
			char info[0x100] = {0x0};
			time_t tm;

			time(&tm);
			snprintf(info, 0x100, "host=%s\nserver=%s\ninterface=%s\nrandnum=%s\ntime=%lu", inet_ntoa( pinfo -> psv -> sin_addr ), pmt -> serverType, pui -> dev, pmt -> randnum, tm);
			fputs(info, fd);
			fclose(fd);
		} else {
			fprintf(stderr, "fopen(%s, \"w\"): %s\n", pmt -> filePath, strerror(errno));
		}

		if ( (pid = fork()) < 0 ) {
			perror("fork");
			exit(EXIT_FAILURE);
		} else if ( pid > 0 ) {
			exit(EXIT_SUCCESS);
		} else if ( pid == 0 ) {
			sendRequestPacket(sockfd, pinfo, 0x3, 0x6);
			exit(EXIT_FAILURE);
		}
	} else if ( mode == 0x3 ) {
		sleep(0x1e);
		sendRequestMode(sockfd, pinfo, mode);
	} else if ( mode == 0x5 ) {
		char *tmp, s[0xc] = {0x0};
		time_t diff;

		time(&diff);
		diff -= (time_t)pmt -> onTime;
		tmp = asctime( gmtime(&diff) );
		memcpy(s, tmp + 0xb, 0x8);

		puts("Leave Internet success!");
		fprintf(stdout, "Your on-line time: %s.\n", s);

		exit(EXIT_SUCCESS);
	} else {
		puts("Developing~~");
		exit(EXIT_SUCCESS);
	}
}

void sendRequestPacket(int sockfd, struct infoset * pinfo, int mode, int timeToRepeat)
{
	int retval;
	int addrlen = sizeof(struct sockaddr);
	struct timeval timeout;
	fd_set rfds;

	timeout.tv_sec = 0x1e;
	timeout.tv_usec = 0x0;

	sendRequestMode(sockfd, pinfo, mode);

	for ( int timeHasRepeat = 0; timeToRepeat > timeHasRepeat; ) {
		int pkgsize = 0x100;
		char * const pkg = (char *)calloc(pkgsize, sizeof(char));

		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		retval = select(sockfd + 1, &rfds, NULL, NULL, (struct timeval *)&timeout);

		if ( retval == -1 ) {
			perror("select");
			exit(EXIT_FAILURE);
		} else if ( retval == 0 ) {
			sendRequestMode(sockfd, pinfo, mode);
			++ timeHasRepeat;
		} else {
			if ( FD_ISSET(sockfd, &rfds) ) {
				pkgsize = recvfrom(sockfd, pkg, pkgsize, 0x0, (struct sockaddr *)(pinfo -> psv), &addrlen);

				if ( pkgsize < 0x0 ) {
					sendRequestMode(sockfd, pinfo, mode);
					++ timeHasRepeat;
				} else {// In this case, free 'pkg' in handlePacket function.
					handlePacket(pkg, pkgsize, sockfd, pinfo, mode);
					timeHasRepeat = 0x0;
				}
			} else {
				++ timeHasRepeat;
			}
		}

		free(pkg);
	}

	if ( mode == 0x1 ) {
		puts("The authentication fails, can't receive respondence from server.");
	} else if ( mode == 0x3 ) {
		puts("Keeping the link fails, can't receive respondence from server.");
	} else if ( mode == 0x5 ) {
		puts("Leaving Internet fails, can't receive respondence from server. But maybe you had leave.");
	} else if ( mode == 0x7 ) {
		puts("Finding the server fails, can't receive respondence from server.");
	}

	exit(EXIT_FAILURE);
}


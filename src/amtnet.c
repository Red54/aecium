#include <stdio.h>		//for perror
#include <wchar.h>
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
#include "md5.h"
#include "amtnet.h"
#define PORT 3848 /* Server Port */

static char *program_mod;
static char version[0x8] = "0.0.0";

bool clearbuf(void)
{
	char c;

	do {
		c =getchar();
	} while (c != '\n');

	return true;
}

void usage(int status)
{
	printf("Usage 1: %s [-h Host] -u Username -p Password [-d Device] [-f]\n", program_mod);
	puts("\t-h Host\t\t\tattestation host IP address.");
	puts("\t-u Username\t\tyour user name.");
	puts("\t-p Password\t\tyour user password.");
	puts("\t-d Device\t\tyour network card interface.");
	puts("\t-f\t\t\tfind server type.");

	printf("\nUsage 2: %s -l\n", program_mod);
	puts("\t-l Leave\t\t\tleave Internet.");

	printf("\nUsage 3: %s -v\n", program_mod);
	puts("\t-v Version\t\tshow program version.");

	exit(status);
}

void get_path(struct mediate *pmt)
{
	char **program_name = &(pmt -> program_name);
	char *filepath = pmt -> filepath;

	if ( program_mod ) {
		*program_name = strrchr(program_mod, '/');
		if ( *program_name ) {
			++ *program_name;
		} else {
			*program_name = program_mod;
		}
	}

	if ( *program_name ) {
		strcpy(filepath, getenv("HOME"));
		strcat(filepath, "/.");
		strcat(filepath, *program_name);
	}	
}

int get_other_pid(char *program_name)
{
	FILE *fd;
	int len = strlen(program_name) + 0x10;
	int pid = 0;
	char cmd[len];

	strcpy(cmd, "ps -A c | grep ");
	strcat(cmd, program_name);

	if ( (fd = popen(cmd, "r")) == NULL ) {
		perror("popen");
		exit(EXIT_FAILURE);
	}

	for( char buf[0x50] = {0x0}; fgets(buf, 0x50, fd); ) {
		if ( strstr(buf, program_name) ) {
			int id = atoi(buf);
			if ( getpid() != atoi(buf) ) {
				pid = id;
				break;
			}
		}
	}

	pclose(fd);

	return pid;
}

void check_arg(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfo_set *pui = pinfo -> pui;
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
				strcpy(pmt -> st, "12net");
				tmp = 1;
			} else {
				usage(EXIT_FAILURE);
			}
		} else if ( !strcmp(s, "-h") ) {
			memcpy(pmt -> host, argv[i + 1], strlen(argv[i + 1]));
		} else if ( !strcmp(s, "-u") ) {
			pui -> usr = argv[i + 1];
		} else if ( !strcmp(s, "-p") ) {
			pui -> pw = argv[i + 1];
		} else if ( !strcmp(s, "-d") ) {
			memcpy(pui -> dev, argv[i + 1], strlen(argv[i + 1]));
		} else if ( !strcmp(s, "-f") ) {
			strcpy(pmt -> st, "12net");
			tmp = 1;
		} else {
			usage(EXIT_FAILURE);
		}

		i += tmp;
	}

}

void info_from_file(struct infoset * const pinfo)
{
		struct usrinfo_set *pui = pinfo -> pui;
		struct mediate *pmt = pinfo -> pmt;
		time_t *on_time = &(pmt -> on_time);
		unsigned int hostlen = strlen(pmt -> host), devlen = strlen(pui -> dev), randlen = strlen(pmt -> randnum), stlen = strlen(pmt -> st);
		FILE *fd;

		if ( (fd = fopen(pmt -> filepath, "r")) == NULL ) {
			printf("fopen(%s, \"r\"): %s\n", pmt -> filepath, strerror(errno));
			usage(EXIT_FAILURE);
		}

		for ( char buf[0x50] = {0x0}; fgets(buf, 0x50, fd); ) {
			char *pos = NULL;

			if ( buf[strlen(buf) - 1] == '\n' ) {
				buf[strlen(buf) - 1] = '\0';
			}

			if ( !devlen ) {
				pos = strstr(buf, "interface=");
				if ( pos ) {
					strcpy(pui -> dev, buf + 0xa);
					devlen = strlen(pui -> dev);
					continue;
				}
			}

			if ( !hostlen ) {
				pos = strstr(buf, "host=");
				if ( pos ) {
					strcpy(pmt -> host, buf + 0x5);
					hostlen = strlen(pmt -> host);
					continue;
				}
			}

			if ( !stlen ) {
				pos = strstr(buf, "server=");
				if ( pos ) {
					strcpy(pmt -> st, buf + 0x7);
					stlen = strlen(pmt -> st);
					continue;
				}
			}

			if ( !randlen ) {
				pos = strstr(buf, "randnum=");
				if ( pos ) {
					strcpy(pmt -> randnum, buf + 0x8);
					randlen = strlen(pmt -> randnum);
					continue;
				}
			}

			if ( !*on_time ) {
				pos = strstr(buf, "time=");
				if ( pos ) {
					*on_time = (time_t)atol(buf + 0x5);
					continue;
				}
			}
		}

		fclose(fd);
}

void get_info(int argc, char **argv, struct infoset * const pinfo)
{
	struct usrinfo_set *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	check_arg(argc, argv, pinfo);

	// When leave, strlen(pmt -> host) absolutely equal zero.
	if ( !strlen(pmt -> host) || !strlen(pui -> dev) || !strlen(pmt -> st) ) {
		info_from_file(pinfo);
	}

	// When argc equal 0x2, 
	if ( strcmp(pmt -> st, "12net") == 0 ) {//&& argc != 0x2 ) {
		memset(pmt -> st, 0x0, 0xc);

		for (int stlen = 0x0; (stlen = strlen(pmt -> st)) == 0; ) {
			char c = 0x0;

			puts("Select service:");
			puts("\t1. int");
			fprintf(stdout, "please select(input \'e\' to Exit):");

			c = getchar();
			clearbuf();

			if ( c == 'e' ) {
				exit(EXIT_SUCCESS);
			} else if ( c == '1' ) {
				strcpy(pmt -> st, "int"); 
			}
		}
	}

	if ( argc == 0x2 ) {
		if ( !( strlen(pmt -> randnum) && strlen(pmt -> host) && strlen(pui -> dev) ) ) {
			fprintf(stderr, "Reading random number, host, or network card interface fails, check the file \"%s\".\n", pmt -> filepath);
			exit(EXIT_FAILURE);
		}
	} else {
		memset(pmt -> randnum, 0x0, 0x20);
		pmt -> on_time = 0x0;

		/*if ( !( strlen(pui -> usr) && strlen(pui -> pw) && strlen(pmt -> host) && strlen(pmt -> st) && strlen(pui -> dev) ) ) {
			usage(EXIT_FAILURE);
		}*/

		if ( !( strlen(pui -> usr) && strlen(pui -> pw) ) ) {
			puts("Please input username and password!");
			usage(EXIT_FAILURE);
		}

		if ( !( strlen(pmt -> host) && strlen(pmt -> st) && strlen(pui -> dev) ) ) {
			fprintf(stderr, "Reading host, network card interface, server type fails, check the file \"%s\".\n", pmt -> filepath);
			usage(EXIT_FAILURE);
		}
	}

}

void server_init(struct infoset * const pinfo)
{
	struct sockaddr_in *psv = pinfo -> psv;
	struct mediate *pmt = pinfo -> pmt;

	memset(psv, 0x0, sizeof(struct sockaddr_in));

	psv -> sin_family = AF_INET;
	psv -> sin_port = htons(PORT);
	psv -> sin_addr.s_addr = inet_addr(pmt -> host);
}

void info_init(int argc, char **argv, struct infoset * const pinfo)
{
	struct mediate *pmt = pinfo -> pmt;

	program_mod = argv[0];

	get_path(pmt);
	get_info(argc, argv, pinfo);

}

void get_addr(int sockfd, struct usrinfo_set * pui)
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

void amtnet(int argc, char **argv)
{
	struct usrinfo_set usrinfo;
	struct sockaddr_in server_addr;
	struct mediate mtinfo;
	struct infoset info;

	info.pui = &usrinfo;
	info.psv = &server_addr;
	info.pmt = &mtinfo;

	memset(&usrinfo, 0x0, sizeof(struct usrinfo_set));
	memset(&mtinfo, 0x0, sizeof(struct mediate));

	info_init(argc, argv, &info);
	server_init(&info);

	// Zero represent leaving, and nonzero accessing.
	start(argc == 0x2 ? 0x0 : 0x1, &info);
}

void chief(struct infoset * pinfo, int a_or_l)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	get_addr(sockfd, pinfo -> pui);

	if ( a_or_l ) {
		send_request_packet(sockfd, pinfo, 0x1, 0x3);
	} else {
		send_request_packet(sockfd, pinfo, 0x5, 0x3);
	}

	close(sockfd);
}

void start(int a_or_l, struct infoset * pinfo)
{
	int other_pid = get_other_pid(pinfo -> pmt -> program_name);

	if ( other_pid ) {
		if ( a_or_l ) {
			fprintf(stderr, "You have already accessed Internet yet!\n");
			exit(EXIT_FAILURE);
		} else {
			if ( kill(other_pid, SIGKILL) == -1 ) {
				perror("kill");
				exit(EXIT_FAILURE);
			} else {
				chief(pinfo, a_or_l);
			}
		}
	} else {
		if ( a_or_l ) {
			chief(pinfo, a_or_l);
		} else {
			fprintf(stderr, "You have not accessed Internet yet!\n");
			exit(EXIT_FAILURE);
		}
	}
}

bool pkg_encrypt(char *s, int len)
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

bool pkg_decrypt(char *s, int len)
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


void send_access_packet(int sockfd, const struct infoset * pinfo)
{
	struct usrinfo_set *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	int usrlen = strlen(pui -> usr), pwlen = strlen(pui -> pw), maclen = 6, iplen = strlen(pui -> ip), stlen = strlen(pmt -> st);
	unsigned int sendbytes = 34 + usrlen + pwlen + iplen + stlen;
	char pkg[sendbytes];
	char *ppkg = pkg;

	memset(ppkg, '\0', sendbytes);

	*ppkg++ = 0x1;
	*ppkg++ = sendbytes;
	ppkg += 0x10;

	*ppkg++ = 0x1;
	*ppkg++ = usrlen + 2;
	memcpy(ppkg, pinfo -> pui -> usr, usrlen);
	ppkg += usrlen;

	*ppkg++ = 0x2;
	*ppkg++ = pwlen + 2;
	memcpy(ppkg, pinfo -> pui -> pw, pwlen);
	ppkg += pwlen;

	*ppkg++ = 0x7;
	*ppkg++ = maclen + 2;
	memcpy(ppkg, pinfo -> pui -> mac, maclen);
	ppkg += maclen;

	*ppkg++ = 0x9;
	*ppkg++ = iplen + 2;
	memcpy(ppkg, pinfo -> pui -> ip, iplen);
	ppkg += iplen;

	*ppkg++ = 0xa;
	*ppkg++ = stlen + 2;
	memcpy(ppkg, pmt -> st, stlen);
	ppkg += stlen;

	MD5Calc(pkg + 2, pkg, sendbytes);

	pkg_encrypt(pkg, sendbytes);

	if ( sendto(sockfd, (unsigned char *)pkg, sendbytes, 0, (struct sockaddr *)(pinfo -> psv), sizeof (struct sockaddr)) == -1 ) {
			perror("sendto");
			exit(EXIT_FAILURE);
	}
}

void send_general_packet(int sockfd, const struct infoset * pinfo, int mode)
{
	struct usrinfo_set *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;

	int iplen = strlen(pui -> ip), maclen = 6, randnumlen = strlen(pmt -> randnum);
	int sendbytes = iplen + maclen + randnumlen + 24;
	char pkg[sendbytes];
	char *ppkg = pkg;

	memset(pkg, '\0', sendbytes);

	*ppkg++ = (char)mode;
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

	MD5Calc(pkg + 2, pkg, sendbytes);
	pkg_encrypt(pkg, sendbytes);

	if ( sendto(sockfd, (unsigned char *)pkg, sendbytes, 0, (struct sockaddr *)(pinfo -> psv), sizeof (struct sockaddr)) == -1 ) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
}

void send_leave_packet(int sockfd, const struct infoset * pinfo)
{
	send_general_packet(sockfd, pinfo, 0x5);
}

void send_keeplink_packet(int sockfd, const struct infoset * pinfo)
{
	send_general_packet(sockfd, pinfo, 0x3);
}

void send_service_packet(int sockfd, const struct infoset * pinfo)
{
	int maclen = 6;
	char pkg[0x1a] = {0};
	char *ppkg = pkg;

	*ppkg ++ = 0x7;
	*ppkg ++ = 0x1a;
	ppkg += 0x10;

	*ppkg++ = 0x7;
	*ppkg++ = maclen + 2;
	memcpy(ppkg, pinfo -> pui -> mac, maclen);
	ppkg += maclen;

	MD5Calc(pkg + 2, pkg, pkg[1]);

	pkg_encrypt(pkg, pkg[1]);

	if ( sendto(sockfd, (unsigned char *)pkg, pkg[1], 0, (struct sockaddr *)(pinfo -> psv), sizeof (struct sockaddr)) == -1 ) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
}

void send_request_cmd(int sockfd, const struct infoset * pinfo, int mode)
{
	if ( mode == 0x1 ) {
		send_access_packet(sockfd, pinfo);
	} else if ( mode == 0x3 ) {
		send_keeplink_packet(sockfd, pinfo);
	} else if ( mode == 0x5 ) {
		send_leave_packet(sockfd, pinfo);
	} else if ( mode == 0x7 ) {
		send_service_packet(sockfd, pinfo);
	} else {
		exit(EXIT_FAILURE);
	}
}

bool check_packet(const char * pkg, int pkgsize)
{
	char md5[0x10] = {0x0};
	char *pkg_cp;
	unsigned char pkglen = (unsigned char)pkg[1];

	if ( pkglen <= pkgsize && pkglen > 0x11) {

		pkg_cp = (char *)malloc(pkglen);
		memcpy(pkg_cp, pkg, pkglen);

		memcpy(md5, pkg_cp + 2, 0x10);
		memset(pkg_cp + 2, 0, 0x10);

		MD5Calc(pkg_cp + 2, pkg_cp, pkglen);

		if ( !memcmp(md5, pkg_cp + 2, 0x10) ) {
			return true;
		}

	}

	return false;
}

void analyze_packet(const char * pkg, char * const randnum, int mode)
{
	char msg[0xff] = {0x0};
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

void handle_packet(char * const pkg, int pkgsize, int sockfd, struct infoset * pinfo, int mode)
{
	struct usrinfo_set *pui = pinfo -> pui;
	struct mediate *pmt = pinfo -> pmt;
	FILE *fd;
	int pid;

	pkg_decrypt(pkg, pkgsize);
	check_packet(pkg, pkgsize);
	analyze_packet(pkg, pmt -> randnum, mode);

	if ( pkg[0] != mode + 0x1 ) {
		puts("Invalid package, or packet mode has been changed!");
		exit(EXIT_FAILURE);
	}

	if ( mode == 0x1 ) {
		puts("The authentication succeeded, and now you can access Internet!");
		if ( fd = fopen(pmt -> filepath, "w") ) {
			char info[0xff] = {0x0};
			time_t tm;

			time(&tm);
			// snprintf(info, 0xff, "host=%s\nserver=%s\ninterface=%s\nnum=%s\ntime=%s", phost, pst, pdev, randnum, on_time);
			snprintf(info, 0xff, "host=%s\nserver=%s\ninterface=%s\nrandnum=%s\ntime=%lu", inet_ntoa( pinfo -> psv -> sin_addr ), pmt -> st, pui -> dev, pmt -> randnum, tm);
			fputs(info, fd);
			fclose(fd);
		} else {
			printf("fopen(%s, \"w\"): %s\n", pmt -> filepath, strerror(errno));
		}

		if ( (pid = fork()) < 0 ) {
			perror("fork");
			exit(EXIT_FAILURE);
		} else if ( pid > 0 ) {
			exit(EXIT_SUCCESS);
		} else if ( pid == 0 ) {
			send_request_packet(sockfd, pinfo, 0x3, 0x6);
		}
	} else if ( mode == 0x3 ) {
		sleep(0x1e);
		send_request_cmd(sockfd, pinfo, mode);
	} else if ( mode == 0x5 ) {
		char *tmp, s[0xc] = {0x0};
		time_t diff;

		time(&diff);
		diff -= pmt -> on_time;
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

void send_request_packet(int sockfd, struct infoset * pinfo, int mode, int ttor)
{
	fd_set rfds;
	int thr, pkgsize, retval;
	int addrlen = sizeof(struct sockaddr);
	char pkg[0xff] = {0x0};
	char *ppkg = pkg;
	struct timeval timeout;

	timeout.tv_sec = 0x1e;
	timeout.tv_usec = 0x0;

	thr = pkgsize = 0;

	send_request_cmd(sockfd, pinfo, mode);

	for ( int thr = 0; ttor > thr; ) {

		FD_ZERO(&rfds);
		FD_SET(sockfd, &rfds);

		retval = select(sockfd + 1, &rfds, NULL, NULL, &timeout);

		if ( retval == -1 ) {
			perror("select");
			exit(EXIT_FAILURE);
		} else if ( retval == 0 ) {
			send_request_cmd(sockfd, pinfo, mode);
			++ thr;
		} else {
			if ( FD_ISSET(sockfd, &rfds) ) {
				memset(pkg, 0x0, sizeof pkg);
				pkgsize = recvfrom(sockfd, ppkg, 0xff, 0, (struct sockaddr *)(pinfo -> psv), &addrlen);

				if ( pkgsize < 0 ) {
					continue;
				}
				
				handle_packet(ppkg, pkgsize, sockfd, pinfo, mode);
				thr = 0;
				continue;
			} else {
				continue;
			}
		}
	}

	if ( false ) {
	} else if ( mode == 0x1 ) {
		puts("The authentication fails, can't receive respondence from server.");
		exit(EXIT_FAILURE);
	} else if ( mode == 0x3 ) {
		puts("Keeping the link fails, can't receive respondence from server.");
		exit(EXIT_FAILURE);
	} else if ( mode == 0x5 ) {
		puts("Leaving Internet fails, can't receive respondence from server. But maybe you had leave.");
		exit(EXIT_FAILURE);
	} else if ( mode == 0x7 ) {
		puts("Finding the server fails, can't receive respondence from server.");
		exit(EXIT_FAILURE);
	}
}


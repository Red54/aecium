/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301,  USA
 */
 
#include <time.h>

struct usrinfo_set {
	char *usr;
	char *pw;
	char dev[0xc];
	char ip[0x10];
	char mac[0x8];
};

struct mediate {
	char st[0xc];
	char host[0x10];
	char randnum[0x20];
	char *program_name;
	char filepath[0xff];
	time_t on_time;
};

struct infoset  {
	struct sockaddr_in * psv;
	struct usrinfo_set * pui;
	struct mediate *pmt;
};

void start(int argc, struct infoset * pinfo);
void info_init(int argc, char **argv, struct infoset * const pinfo);
void send_request_packet(int sockfd, struct infoset * pinfo, int mode, int ttor);//,  struct timeval * timeout)

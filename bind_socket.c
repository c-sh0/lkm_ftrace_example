/*
 * bind() a socket() to address and port
 *
 * $ gcc -Wall bind_socket.c -o bind_socket
 *
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <pwd.h>

/* TCP/IP port numbers below 1024 are special in that normal users are
 * not allowed to bind services on them */
#define BIND_PORT 12

int main(int argc, char **argv) {

	char l_addr[16];
	int sockfd, l_port;
	struct sockaddr_in self, s_addr;
        struct ifreq ifr;
	struct passwd *pw;
	socklen_t len;
	uid_t uid;

	/* note: bzero() is not a standard C function */
        bzero(&ifr, sizeof(ifr));
	bzero(&self, sizeof(self));
	bzero(&s_addr, sizeof(s_addr));

	/* get uid,gid of the user running this program */
	len = sizeof(s_addr);
	uid = getuid();
	pw  = getpwuid(uid); /* getpwuid(3) - no need pass the returned pointer to free(3) */

	printf("uname:%s uid:%d gid:%d\n", pw->pw_name, pw->pw_uid, pw->pw_gid);

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0))== -1) {
                perror("Error creating socket:");
                exit(-1);
        }

	self.sin_family		= AF_INET;
	self.sin_port		= htons(BIND_PORT);
	self.sin_addr.s_addr	= INADDR_ANY;

        if((bind(sockfd, (struct sockaddr *)&self, sizeof(self)))== -1) {
                perror("Error binding socket to interface\n");
               exit(-1);
        }

	printf("bind() port:%d succeeded\n",BIND_PORT);

	/* get ip address and port info from the socket */
	getsockname(sockfd, (struct sockaddr *)&s_addr, &len);
	inet_ntop(AF_INET, &s_addr.sin_addr, l_addr, sizeof(l_addr));
	l_port = ntohs(s_addr.sin_port);

	printf("ipaddr:%s port:%u\n",l_addr,l_port);

	printf("exit\n");
	close(sockfd);

  return(0);
}

#ifndef XTCP_H
#define XTCP_H

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <poll.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/epoll.h>


typedef int (*SocketFunc)(int domain, int type, int protocol);
typedef int (*BindFunc)(int sockfd, const struct sockaddr* addr, socklen_t addr_len);
typedef int (*ListenFunc)(int sockfd, int backlog);
typedef int (*AcceptFunc)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*EpollWaitFunc)(int epfd, struct epoll_event *events, int maxevents, int timeout);
typedef int (*WriteFunc)(int fd, const void *buf, size_t count);
typedef int (*ReadFunc)(int fd, void *buf, size_t count);
typedef int (*ConnectFunc)(int sockfd, const struct sockaddr *address, socklen_t address_len);
typedef ssize_t (*SendFunc)(int sockfd, const void *buf, size_t len, int flags);
typedef ssize_t (*RecvFunc)(int sockfd, void *buf, size_t len, int flags);
typedef int (*SelectFunc)(int nfds, fd_set *readfds, fd_set *writefds,
        fd_set *exceptfds, struct timeval *timeout);
typedef int (*CloseFunc)(int fd);

#endif

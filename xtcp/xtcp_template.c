#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "xtcp.h"
#include "xtcp_util.h"

static void init() __attribute__((constructor));

typedef struct libc_func_s {
    SocketFunc socket;
    BindFunc bind;
    ListenFunc listen;
    AcceptFunc accept;
    EpollWaitFunc epoll_wait;
    WriteFunc write;
    ReadFunc read;
    ConnectFunc connect;
    SendFunc send;
    RecvFunc recv;
    SelectFunc select;
    CloseFunc close;
} libc_func_t;

libc_func_t libc;

#define SETSYM_OR_FAIL(func) { \
	dlerror(); \
	libc.func = dlsym(RTLD_NEXT, #func); \
	char* errorMessage = dlerror(); \
	if(errorMessage != NULL) { \
		fprintf(stderr, "dlsym(%s): dlerror(): %s\n", #func, errorMessage); \
		exit(EXIT_FAILURE); \
	} else if(libc.func == NULL) { \
		fprintf(stderr, "dlsym(%s): returned NULL pointer\n", #func); \
		exit(EXIT_FAILURE); \
	} \
}

void init() {
    SETSYM_OR_FAIL(socket);
    SETSYM_OR_FAIL(bind);
    SETSYM_OR_FAIL(listen);
    SETSYM_OR_FAIL(accept);
    SETSYM_OR_FAIL(epoll_wait);
    SETSYM_OR_FAIL(write);
    SETSYM_OR_FAIL(read);
    SETSYM_OR_FAIL(connect);
    SETSYM_OR_FAIL(send);
    SETSYM_OR_FAIL(recv);
    SETSYM_OR_FAIL(select);
    SETSYM_OR_FAIL(close);

    xtcp_debug("initialized all interposed functions");
}


int socket(int domain, int type, int protocol) {
    int sockfd = libc.socket(domain, type, protocol);
    xtcp_debug("socket %d created", sockfd);

    return sockfd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    xtcp_debug("bind on socket %d", sockfd);
    return libc.bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    xtcp_debug("listen on socket %d", sockfd);
    return libc.listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    xtcp_debug("accept on socket %d", sockfd);
    return libc.accept(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *address, socklen_t address_len) {
    xtcp_debug("connect on socket %d", sockfd);
    return libc.connect(sockfd, address, address_len);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    xtcp_debug("send %d bytes on socket %d", len, sockfd);
    return libc.send(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    xtcp_debug("recv %d bytes on socket %d", len, sockfd);
    return libc.recv(sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    xtcp_debug("write %d bytes on fd %d", count, fd);
    return libc.write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    xtcp_debug("read %d bytes on fd %d", count, fd);
    return libc.read(fd, buf, count);
}

int close(int fd) {
    xtcp_debug("close fd %d", fd);
    return libc.close(fd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *expectfds, struct timeval *timeout) {
    xtcp_debug("select on %d fds", nfds);
    return libc.select(nfds, readfds, writefds, expectfds, timeout);
}

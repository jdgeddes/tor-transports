#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include "xtcp.h"
#include "xtcp_util.h"

static void init() __attribute__((constructor));

typedef struct libc_func_s {
    SocketFunc socket;
    BindFunc bind;
    ListenFunc listen;
    AcceptFunc accept;
    WriteFunc write;
    ReadFunc read;
    ConnectFunc connect;
    SendFunc send;
    RecvFunc recv;
    CloseFunc close;
    EpollCtlFunc epoll_ctl;
    EpollWaitFunc epoll_wait;
    SelectFunc select;
} libc_func_t;


typedef struct global_data_s {
    libc_func_t libc;
} global_data_t;

global_data_t global_data;
global_data_t *global_data_pointer = &global_data;
int global_data_size = sizeof(global_data);

#define SETSYM_OR_FAIL(func) { \
	dlerror(); \
	global_data.libc.func = dlsym(RTLD_NEXT, #func); \
	char* errorMessage = dlerror(); \
	if(errorMessage != NULL) { \
		fprintf(stderr, "dlsym(%s): dlerror(): %s\n", #func, errorMessage); \
		exit(EXIT_FAILURE); \
	} else if(global_data.libc.func == NULL) { \
		fprintf(stderr, "dlsym(%s): returned NULL pointer\n", #func); \
		exit(EXIT_FAILURE); \
	} \
}

void init_lib() {
    SETSYM_OR_FAIL(socket);
    SETSYM_OR_FAIL(bind);
    SETSYM_OR_FAIL(listen);
    SETSYM_OR_FAIL(accept);
    SETSYM_OR_FAIL(write);
    SETSYM_OR_FAIL(read);
    SETSYM_OR_FAIL(connect);
    SETSYM_OR_FAIL(send);
    SETSYM_OR_FAIL(recv);
    SETSYM_OR_FAIL(close);
    SETSYM_OR_FAIL(epoll_ctl);
    SETSYM_OR_FAIL(epoll_wait);
    SETSYM_OR_FAIL(select);

    xtcp_info("initialized all interposed functions");
}

void init() {
    char *inShadow = getenv("SHADOW_SPAWNED");
    if(!inShadow) {
        xtcp_info("init template");
        init_lib();
    }
}

int socket(int domain, int type, int protocol) {
    int sockfd = global_data.libc.socket(domain, type, protocol);
    xtcp_info("socket %d created", sockfd);
    return sockfd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    xtcp_info("bind on socket %d", sockfd);
    return global_data.libc.bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    xtcp_info("listen on socket %d", sockfd);
    return global_data.libc.listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    xtcp_info("accept on socket %d", sockfd);
    return global_data.libc.accept(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *address, socklen_t address_len) {
    xtcp_info("connect on socket %d", sockfd);
    return global_data.libc.connect(sockfd, address, address_len);
}

void print_tcp_info(int sockfd) {
    struct tcp_info tcp_info;
    socklen_t tcp_info_len = sizeof(tcp_info);

    if(getsockopt(sockfd, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_len) == 0) {
        /*xtcp_info("sockfd %d cwnd %u ssthresh %u rtt %u lost %u retrans %u", sockfd, */
                /*tcp_info.tcpi_snd_cwnd, tcp_info.tcpi_snd_ssthresh,*/
                /*tcp_info.tcpi_rtt, tcp_info.tcpi_lost, tcp_info.tcpi_retrans);*/
    }
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    ssize_t ret = global_data.libc.send(sockfd, buf, len, flags);
    xtcp_info("send %lu bytes on socket %d", ret, sockfd);

    return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    ssize_t ret = global_data.libc.recv(sockfd, buf, len, flags);
    xtcp_info("recv %d bytes on socket %d", ret, sockfd);

    print_tcp_info(sockfd);

    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t ret = global_data.libc.write(fd, buf, count);
    xtcp_info("write %d bytes on fd %d", ret, fd);
    /*print_tcp_info(fd);*/
    return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
    ssize_t ret = global_data.libc.read(fd, buf, count);
    xtcp_info("read %d bytes on fd %d", ret, fd);
    /*print_tcp_info(fd);*/
    return ret;
}

int close(int fd) {
    xtcp_info("close fd %d", fd);
    return global_data.libc.close(fd);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    xtcp_info("epoll_ctl epfd %d op %d fd %d", epfd, op, fd);
    return global_data.libc.epoll_ctl(epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    xtcp_info("epoll_wait on %d", epfd);
    int i;
    int nfds = global_data.libc.epoll_wait(epfd, events, maxevents, timeout);
    for(i = 0; i < nfds; i++) {
        xtcp_info("fd %d has events %d", events[i].data.fd, events[i].events);
    }
    return nfds;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *expectfds, struct timeval *timeout) {
    xtcp_info("select on %d fds", nfds);
    return global_data.libc.select(nfds, readfds, writefds, expectfds, timeout);
}

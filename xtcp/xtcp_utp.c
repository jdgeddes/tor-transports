#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "xtcp.h"
#include "xtcp_util.h"

#include "libs/libutp/utp.h"

static void init() __attribute__((constructor));

uint64 utp_log_cb(utp_callback_arguments *a);
uint64 utp_sendto_cb(utp_callback_arguments *a);
uint64 utp_on_state_change_cb(utp_callback_arguments *a);
uint64 utp_on_error_cb(utp_callback_arguments *a);
uint64 utp_on_accept_cb(utp_callback_arguments *a);
uint64 utp_on_read_cb(utp_callback_arguments *a);

typedef struct utp_context_data_s {
    int sockfd;
    int nonblock;
    queue_t *socketq;
} utp_context_data_t;

typedef struct utp_socket_data_s {
    int sockfd;
    int connected;
    int writeable;
    int closed;
    buffer_t *readbuf;
} utp_socket_data_t;

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
    hashtable_t *sockfd_to_context;
    hashtable_t *sockfd_to_socket;
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

    global_data.sockfd_to_context = hashtable_create();
    global_data.sockfd_to_socket = hashtable_create();

    xtcp_debug("initialized all interposed functions");
}

void init() {
    init_lib();
}


/**
 * Callback Functions
 **/
uint64 utp_log_cb(utp_callback_arguments *a) {
    xtcp_info("[utp-log] %s", a->buf);
	return 0;
}

uint64 utp_sendto_cb(utp_callback_arguments *a) {
    utp_context *ctx = a->context;
    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    if(!ctxdata) {
        xtcp_error("could not find context data");
        return -1;
    }

    if(sendto(ctxdata->sockfd, a->buf, a->len, 0, a->address, a->address_len) < 0) {
        xtcp_error("error sending %d bytes on socket %d: %s", a->len, ctxdata->sockfd, strerror(errno));
        return -1;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *) a->address;
    xtcp_info("sendto %d: %zd byte packet to %s:%d%s", ctxdata->sockfd, a->len,
            inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
            (a->flags & UTP_UDP_DONTFRAG) ? " (DF bit request but not yet implemented)" :"");


	return 0;
}

uint64 utp_on_state_change_cb(utp_callback_arguments *a) {
    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(a->socket);
	xtcp_debug("[utp] state %d: %s, sockfd %d\n", a->state, utp_state_names[a->state], sdata->sockfd);

	switch (a->state) {
		case UTP_STATE_CONNECT:
            sdata->connected = 1;
		case UTP_STATE_WRITABLE:
            sdata->writeable = 1;
			break;

		case UTP_STATE_EOF:
			xtcp_info("[utp] received EOF from socket; closing\n");
            sdata->closed = 1;
            utp_close(a->socket);
			break;

		case UTP_STATE_DESTROYING:
			xtcp_info("[utp] UTP socket is being destroyed; exiting\n");

            sdata->closed = 1;
            utp_socket_stats *stats = utp_get_stats(a->socket);
            if (stats) {
                xtcp_info("Socket Statistics:");
                xtcp_info("    Bytes sent:          %lu", stats->nbytes_xmit);
                xtcp_info("    Bytes received:      %lu", stats->nbytes_recv);
                xtcp_info("    Packets received:    %lu", stats->nrecv);
                xtcp_info("    Packets sent:        %lu", stats->nxmit);
                xtcp_info("    Duplicate receives:  %lu", stats->nduprecv);
                xtcp_info("    Retransmits:         %lu", stats->rexmit);
                xtcp_info("    Fast Retransmits:    %lu", stats->fastrexmit);
                xtcp_info("    Best guess at MTU:   %lu", stats->mtu_guess);
            } else {
                xtcp_info("No socket statistics available");
            }

			break;
	}

	return 0;
}

uint64 utp_on_error_cb(utp_callback_arguments *a) {
	xtcp_error("[utp] %s\n", utp_error_code_names[a->error_code]);

    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(a->socket);
    sdata->closed = 1;
	return 0;
}


uint64 utp_on_accept_cb(utp_callback_arguments *a) {
    utp_context *ctx = a->context;
    utp_socket *s = a->socket;

    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    if(!ctxdata) {
        xtcp_error("could not find context data");
        return -1;
    }

    utp_socket_data_t *sdata = (utp_socket_data_t *)malloc(sizeof(*sdata));
    memset(sdata, 0, sizeof(*sdata));
    sdata->readbuf = buffer_new();
    sdata->connected = 1;
    sdata->writeable = 1;
    utp_set_userdata(s, sdata);

    /* push socket into incoming queue */
    queue_push(&ctxdata->socketq, s);

    xtcp_info("added utp socket for fd %d", ctxdata->sockfd);

	return 0;
}

/*uint64 callback_on_firewall(utp_callback_arguments *a) {*/
	/*fprintf(stderr, "Firewall allowing inbound connection\n");*/
	/*return 0;*/
/*}*/

uint64 utp_on_read_cb(utp_callback_arguments *a) {
    utp_socket *s = a->socket;
    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
    buffer_append(sdata->readbuf, (unsigned char *)a->buf, a->len);
    utp_read_drained(s);

    xtcp_info("read in %lu bytes", a->len);

	return 0;
}

utp_context *utp_create_context(int sockfd, int nonblock) {
    utp_context *ctx = utp_init(2);
    utp_set_callback(ctx, UTP_LOG, &utp_log_cb);
    utp_set_callback(ctx, UTP_SENDTO, &utp_sendto_cb);
    utp_set_callback(ctx, UTP_ON_ERROR, &utp_on_error_cb);
    utp_set_callback(ctx, UTP_ON_STATE_CHANGE, &utp_on_state_change_cb);
    utp_set_callback(ctx, UTP_ON_READ, &utp_on_read_cb);
    utp_set_callback(ctx, UTP_ON_ACCEPT, &utp_on_accept_cb);

    utp_context_set_option(ctx, UTP_LOG_NORMAL, 1);
    /*if(xtcp_log_level() <= XTCP_LOG_DEBUG) {*/
        utp_context_set_option(ctx, UTP_LOG_MTU, 1);
        utp_context_set_option(ctx, UTP_LOG_DEBUG, 1);
    /*}*/

    utp_context_data_t *ctxdata = (utp_context_data_t *)malloc(sizeof(*ctxdata));
    memset(ctxdata, 0, sizeof(*ctxdata));
    ctxdata->sockfd = sockfd;
    ctxdata->nonblock = nonblock;

    utp_context_set_userdata(ctx, ctxdata);

    return ctx;
}

int utp_read_context(utp_context *ctx, utp_context_data_t *ctxdata) {
    assert(ctx && ctxdata);

    /*struct pollfd p[1];*/
    /*p[0].fd = ctxdata->sockfd;*/
    /*p[0].events = POLLIN;*/

    /*if(!poll(p, 1, 0)) {*/
        /*return 0;*/
    /*}*/

    /*if(!(p[0].revents & POLLIN)) {*/
        /*return 0;*/
    /*}*/

    char buf[4096];
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    while(1) {
        int len = recvfrom(ctxdata->sockfd, buf, sizeof(buf),
                MSG_DONTWAIT, (struct sockaddr *)&addr, &addrlen);

        xtcp_debug("read in %d bytes on socket %d", len, ctxdata->sockfd);

        if(len < 0) {
            if(errno == EAGAIN || errno == EWOULDBLOCK) {
                utp_issue_deferred_acks(ctx);
                break;
            } else {
                xtcp_debug("recv on %d: %s", ctxdata->sockfd, strerror(errno));
                return -1;
            }
        }

        /* have UTP process the data we just read */
        if(!utp_process_udp(ctx, (const byte *)buf, len, (struct sockaddr *)&addr, addrlen)) {
            xtcp_debug("packet not handled by UTP, ignoring");
        }
    }

    return 0;
}
        

/*
 * Interposed functions
 */

int socket(int domain, int type, int protocol) {
    if(!(type & SOCK_STREAM)) {
        return global_data.libc.socket(domain, type, protocol);
    }

    /* switch type from STREAM to DGRAM */
    type = (type & ~SOCK_STREAM) | SOCK_DGRAM;
    int sockfd = global_data.libc.socket(AF_INET, type, IPPROTO_UDP);
    utp_context *ctx = utp_create_context(sockfd, (type & SOCK_NONBLOCK));

    int on = 1;
    setsockopt(sockfd, SOL_IP, IP_RECVERR, &on, sizeof(on));

    /* add socket to context mapping */
    if(hashtable_insert(global_data.sockfd_to_context, sockfd, (void *)ctx)) {
        xtcp_warning("inserted socket %d which was already assigned to a context", sockfd);
    }

    xtcp_info("created socket %d which is %sblocking", sockfd, (type & SOCK_NONBLOCK) ? "non-" : "");

    return sockfd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    xtcp_debug("bind on socket %d", sockfd);

    utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_context, sockfd);
    if(!ctx) {
        xtcp_debug("no context for %d, not a TCP socket", sockfd);
        return global_data.libc.bind(sockfd, addr, addrlen);
    }

    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    if(!ctxdata) {
        xtcp_error("no UTP data for socket %d", sockfd);
        return -1;
    }

    return global_data.libc.bind(ctxdata->sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    xtcp_debug("listen on socket %d", sockfd);
    if(!hashtable_lookup(global_data.sockfd_to_context, sockfd)) {
        return global_data.libc.listen(sockfd, backlog);
    }
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    xtcp_debug("accept on socket %d", sockfd);

    utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_context, sockfd);
    if(!ctx) {
        xtcp_debug("not utp context for socket %d, passing through", sockfd);
        return global_data.libc.accept(sockfd, addr, addrlen);
    }

    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    if(!ctxdata) {
        xtcp_error("not context data for socket %d", sockfd);
        return -1;
    }

    /* if the UTP context is nonblock and no incoming sockets are in
     * the queue, block and keep reading until we have one */
    while(!ctxdata->nonblock && queue_length(ctxdata->socketq) == 0) {
        if(utp_read_context(ctx, ctxdata) < 0) {
            return -1;
        }
    }

    /* get a socket from the queue, if we don't have one return block */
    utp_socket *s = (utp_socket *)queue_pop(&ctxdata->socketq);
    if(!s) {
        errno = EWOULDBLOCK;
        return -1;
    }
    if(addr) {
       utp_getpeername(s, addr, addrlen);
    }

    /* create new child socket for the new connection */
    int type = SOCK_DGRAM;
    if(ctxdata->nonblock) {
        type |= SOCK_NONBLOCK;
    }
    int newsockfd = global_data.libc.socket(AF_INET, type, 0);


    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
    sdata->sockfd = newsockfd;

    hashtable_insert(global_data.sockfd_to_socket, newsockfd, s);

    return newsockfd;
}

int connect(int sockfd, const struct sockaddr *address, socklen_t address_len) {
    xtcp_debug("connect on socket %d", sockfd);
    
    utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_context, sockfd);
    if(!ctx) {
        xtcp_debug("no context for socket %d, skipping");
        return global_data.libc.connect(sockfd, address, address_len);
    }

    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    if(!ctxdata) {
        xtcp_error("no context data for socket %d", sockfd);
        return -1;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if(getaddrinfo("0.0.0.0", NULL, &hints, &res) != 0) {
        xtcp_error("socket %d: getaddrifo: %s", sockfd, strerror(errno));
        return -1;
    }

    if(global_data.libc.bind(ctxdata->sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        xtcp_error("socket %d: bind: %s", sockfd, strerror(errno));
        return -1;
    }

    utp_socket *s = utp_create_socket(ctx);
    utp_socket_data_t *sdata = (utp_socket_data_t *)malloc(sizeof(*sdata));
    memset(sdata, 0, sizeof(*sdata));
    sdata->readbuf = buffer_new();
    sdata->sockfd = sockfd;
    utp_set_userdata(s, sdata);

    utp_connect(s, address, address_len);

    hashtable_insert(global_data.sockfd_to_socket, sockfd, s);

    return 0;
}

ssize_t mysend(int sockfd, const void *buf, size_t len, int flags) {
    xtcp_debug("send %d bytes on socket %d", len, sockfd);

    utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, sockfd);
    if(!s) {
        return global_data.libc.send(sockfd, buf, len, flags);
    }

    utp_context *ctx = utp_get_context(s);
    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);

    /* if closed return 0 so application knows */
    if(sdata->closed) {
        return 0;
    }

    /* if the socket is blocking and we're not connected, keep reading in
     * on the context until the handshake is completed so we can send */
    while(!ctxdata->nonblock && !sdata->connected) {
        if(utp_read_context(ctx, ctxdata) < 0) {
            return -1;
        }
    }

    size_t bytes = utp_write(s, (void *)buf, len);
    xtcp_debug("wrote %d bytes on socket %d", bytes, sockfd);
    if(bytes == 0) {
        errno = EWOULDBLOCK;
        return -1;
    }

    return bytes;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    return mysend(sockfd, buf, len, flags);
}

ssize_t myrecv(int sockfd, void *buf, size_t len, int flags) {
    xtcp_debug("recv %d bytes on socket %d", len, sockfd);

    utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, sockfd);
    if(!s) {
        return global_data.libc.recv(sockfd, buf, len, flags);
    }

    utp_context *ctx = utp_get_context(s);
    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);

    /* if closed return 0 so application knows */
    if(sdata->closed) {
        return 0;
    }

    /* if the socket is blocking, wait until we have enough bytes to fill the buffer */
    while(!ctxdata->nonblock && (size_t)buffer_length(sdata->readbuf) < len) {
        if(utp_read_context(ctx, ctxdata) < 0) {
            return -1;
        }
    }

    len = MIN(len, buffer_length(sdata->readbuf));
    if(len == 0) {
        errno = EWOULDBLOCK;
        return -1;
    }

    buffer_pop_bytes(sdata->readbuf, (unsigned char *)buf, len);

    return len;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    return myrecv(sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    /*xtcp_debug("write %d bytes on fd %d", count, fd);*/
    
    utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, fd);
    if(!s) {
        return global_data.libc.write(fd, buf, count);
    }

    return mysend(fd, buf, count, 0);
}

ssize_t read(int fd, void *buf, size_t count) {
    /*xtcp_debug("read %d bytes on fd %d", count, fd);*/

    utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, fd);
    if(!s) {
        return global_data.libc.read(fd, buf, count);
    }

    return myrecv(fd, buf, count, 0);
}

int close(int fd) {
    utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_socket, fd);
    utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, fd);
    if(!s) {
        return global_data.libc.close(fd);
    }

    xtcp_info("closing socket %d", fd);
    if(ctx) {
        hashtable_remove(global_data.sockfd_to_context, fd);
    }
    hashtable_remove(global_data.sockfd_to_socket, fd);
    utp_close(s);

    return 0;
}

/*
 * Poll/Select functions
 */
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    xtcp_debug("epoll_ctl epfd %d op %d fd %d", epfd, op, fd);
    utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_context, fd);
    utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, fd);
    if(ctx && event) {
        event->events &= ~EPOLLOUT;
    }
    if(!ctx && s && event) {
        event->events &= ~(EPOLLIN | EPOLLOUT);
    }
    return global_data.libc.epoll_ctl(epfd, op, fd, event);    
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    xtcp_debug("epoll_wait on ep %d", epfd);
    
    struct epoll_event *evs = (struct epoll_event *)malloc(maxevents * sizeof(struct epoll_event));
    int nevents = global_data.libc.epoll_wait(epfd, evs, maxevents, timeout);

    xtcp_debug("epoll_wait returned %d fds", nevents);

    int i, nfds = 0;
    for(i = 0; i < nevents; i++) {
        int fd = evs[i].data.fd;
        int ev = evs[i].events;

        xtcp_debug("fd %d has events %d", fd, ev);

        utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_context, fd);
        if(ctx) {
            utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
            if(!ctxdata) {
                xtcp_error("no context data for socket %d", fd);
                return -1;
            }

            if(utp_read_context(ctx, ctxdata) < 0) {
            }

            if(queue_length(ctxdata->socketq) > 0) {
                events[nfds].data.fd = fd;
                events[nfds].events = EPOLLIN;
                nfds++;
            }

            utp_check_timeouts(ctx);
        } else if(!hashtable_lookup(global_data.sockfd_to_socket, fd)) {
            memcpy(&events[nfds], &evs[i], sizeof(struct epoll_event));
            nfds++;
        }
    }

    int idx = 0;
    void **sockets = hashtable_getvalues(global_data.sockfd_to_socket);
    while(sockets[idx]) {
        utp_socket *s = (utp_socket *)sockets[idx];
        utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
        if(!sdata) {
            xtcp_error("no utp socket for socket %p", s);
            return -1;
        }

        int ev = 0;
        if(buffer_length(sdata->readbuf) > 0) {
            ev |= EPOLLIN;
        }
        if(sdata->writeable) {
            ev |= EPOLLOUT;
        }
        xtcp_debug("socket %d has event %d", sdata->sockfd, ev);
        if(ev) {
            events[nfds].data.fd = sdata->sockfd;
            events[nfds].events = ev;
            nfds++;
        }

        idx++;
    }

    free(evs);

    xtcp_debug("returning %d events", nfds);

    return nfds;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *expectfds, struct timeval *timeout) {
    xtcp_debug("select on %d fds", nfds);

    int fd;
    int ret = global_data.libc.select(nfds, readfds, writefds, expectfds, timeout);

    if(ret < 0) {
        xtcp_debug("select return error %d: %s", ret, strerror(errno));
        return ret;
    }

    xtcp_debug("select returned %d", ret);

    for(fd = 0; fd < nfds; fd++) {
        if(readfds && FD_ISSET(fd, readfds)) {
            xtcp_debug("fd %d is ready to read", fd);
        }
        if(writefds && FD_ISSET(fd, writefds)) {
            xtcp_debug("fd %d is ready to write", fd);
        }

        utp_context *ctx = (utp_context *)hashtable_lookup(global_data.sockfd_to_context, fd);
        if(ctx) {
            utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
            if(!ctxdata) {
                xtcp_error("no context data for socket %d", fd);
                return -1;
            }

            utp_read_context(ctx, ctxdata);

            if(queue_length(ctxdata->socketq) > 0 && readfds && !FD_ISSET(fd, readfds)) {
                xtcp_debug("socket to accept, marking %d as readable", fd);
                FD_SET(fd, readfds);
                ret++;
            }

            utp_check_timeouts(ctx);
        }

        utp_socket *s = (utp_socket *)hashtable_lookup(global_data.sockfd_to_socket, fd);
        if(s) {
            utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
            if(!sdata) {
                xtcp_error("no utp socket for socket %d", fd);
                return -1;
            }

            if(readfds && FD_ISSET(fd, readfds)) {
                FD_CLR(fd, readfds);
                ret--;
                if(buffer_length(sdata->readbuf) > 0) {
                    xtcp_debug("marking fd %d as readable", fd);
                    FD_SET(fd, readfds);
                    ret++;
                }
            }

            if(writefds && FD_ISSET(fd, writefds)) {
                FD_CLR(fd, writefds);
                ret--;
                if(sdata->writeable) {
                    xtcp_debug("marking fd %d as writeable", fd);
                    FD_SET(fd, writefds);
                    ret++;
                }
            }
        }
    }

    xtcp_debug("select returning %d", ret);

    return ret;
}

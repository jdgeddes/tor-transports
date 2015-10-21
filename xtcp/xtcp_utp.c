#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include <glib.h>

#include "xtcp.h"
#include "xtcp_util.h"

#include "libs/libutp/utp.h"

#define ONE_MILLISECOND 1000000
#define ONE_SECOND 1000000000

static void init() __attribute__((constructor));

uint64 utp_log_cb(utp_callback_arguments *a);
uint64 utp_sendto_cb(utp_callback_arguments *a);
uint64 utp_on_state_change_cb(utp_callback_arguments *a);
uint64 utp_on_error_cb(utp_callback_arguments *a);
uint64 utp_on_accept_cb(utp_callback_arguments *a);
uint64 utp_on_read_cb(utp_callback_arguments *a);

typedef struct utp_context_data_s {
    int sockfd;
    int timerfd;
    int nonblock;
    int closed;
    int epollfd;
    struct epoll_event epollev;
    GQueue *socketq;
} utp_context_data_t;

typedef struct utp_socket_data_s {
    int sockfd;
    int connected;
    int writeable;
    int closed;
    int eof;
    GByteArray *readbuf;
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
    GHashTable *timerfd_to_context;
    GHashTable *sockfd_to_context;
    GHashTable *sockfd_to_socket;
} global_data_t;

global_data_t global_data;
global_data_t *global_data_pointer = &global_data;
int global_data_size = sizeof(global_data);

#define SETSYM_OR_FAIL(func) { \
	dlerror(); \
	global_data.libc.func = dlsym(RTLD_NEXT, #func); \
	char* errorMessage = dlerror(); \
	if(errorMessage != NULL) { \
		fprintf(stderr, "dlsym(%s): dlerror(): %s", #func, errorMessage); \
		exit(EXIT_FAILURE); \
	} else if(global_data.libc.func == NULL) { \
		fprintf(stderr, "dlsym(%s): returned NULL pointer", #func); \
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

    global_data.timerfd_to_context = g_hash_table_new(g_direct_hash, g_direct_equal);
    global_data.sockfd_to_context = g_hash_table_new(g_direct_hash, g_direct_equal);
    global_data.sockfd_to_socket = g_hash_table_new(g_direct_hash, g_direct_equal);

    xtcp_debug("initialized all interposed functions");
}

void init() {
    init_lib();
}

/**
 * Helper uTP functions
 **/

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
    ctxdata->socketq = g_queue_new();
    g_queue_init(ctxdata->socketq);

    utp_context_set_userdata(ctx, ctxdata);

    /* setup timer to check for timeouts every 500 ms */
    struct itimerspec its;
    struct timespec start_time;
    unsigned long interval = 500 * ONE_MILLISECOND;

    clock_gettime(CLOCK_REALTIME, &start_time);

    start_time.tv_nsec += interval;
    if(start_time.tv_nsec > ONE_SECOND) {
        start_time.tv_sec += 1;
        start_time.tv_nsec -= ONE_SECOND;
    }

    its.it_value.tv_sec = start_time.tv_sec;
    its.it_value.tv_nsec = start_time.tv_nsec;
    its.it_interval.tv_sec = interval / ONE_SECOND;
    its.it_interval.tv_nsec = interval % ONE_SECOND;

    ctxdata->timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if(ctxdata->timerfd == -1) {
        xtcp_error("error calling timerfd_create");
        return NULL;
    }

    if(timerfd_settime(ctxdata->timerfd, TFD_TIMER_ABSTIME, &its, NULL) == -1) {
        xtcp_error("error setting time for timerfd %d", ctxdata->timerfd);
    }

    return ctx;
}

void utp_destroy_socket(int sockfd) {
    utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context,
            GINT_TO_POINTER(sockfd));
    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket,
            GINT_TO_POINTER(sockfd));

    xtcp_debug("destroying socket %d (%p %p)", sockfd, ctx, s);

    if(ctx) {
        utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);

        /* remove the sockfd and timerfd from epoll */
        struct epoll_event ev;

        ev.data.fd = ctxdata->sockfd;
        ev.events = EPOLLIN | EPOLLOUT;
        global_data.libc.epoll_ctl(ctxdata->epollfd, EPOLL_CTL_DEL, ctxdata->sockfd, &ev);

        ev.data.fd = ctxdata->sockfd;
        ev.events = EPOLLIN | EPOLLET;
        global_data.libc.epoll_ctl(ctxdata->epollfd, EPOLL_CTL_DEL, ctxdata->timerfd, &ev);

        close(ctxdata->timerfd);
        close(ctxdata->sockfd);
        free(ctxdata);

        g_hash_table_remove(global_data.sockfd_to_context, GINT_TO_POINTER(sockfd));
    }

    if(s) {
        utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
        free(sdata);
        g_hash_table_remove(global_data.sockfd_to_socket, GINT_TO_POINTER(sockfd));
    }
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
	xtcp_debug("[utp] state %d: %s, sockfd %d", a->state, utp_state_names[a->state], sdata->sockfd);

	switch (a->state) {
		case UTP_STATE_CONNECT:
            sdata->connected = 1;
		case UTP_STATE_WRITABLE:
            sdata->writeable = 1;

            utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
                    GINT_TO_POINTER(sdata->sockfd));
            if(ctx) {
                utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
                struct epoll_event ev;
                ev.data.fd = ctxdata->sockfd;
                ev.events = EPOLLIN | EPOLLOUT;
                global_data.libc.epoll_ctl(ctxdata->epollfd, EPOLL_CTL_MOD, ctxdata->sockfd, &ev);
            }
			break;

		case UTP_STATE_EOF:
			xtcp_info("[utp] received EOF from socket");
            sdata->eof = 1;
			break;

		case UTP_STATE_DESTROYING:
			xtcp_info("[utp] UTP socket is being destroyed; exiting");

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

            utp_destroy_socket(sdata->sockfd);

			break;
	}

	return 0;
}

uint64 utp_on_error_cb(utp_callback_arguments *a) {
	xtcp_error("[utp] %s", utp_error_code_names[a->error_code]);

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
    sdata->readbuf = g_byte_array_new();
    sdata->connected = 0;
    sdata->writeable = 1;
    utp_set_userdata(s, sdata);

    /* push socket into incoming queue */
    g_queue_push_tail(ctxdata->socketq, s);

    struct sockaddr_in *addr = (struct sockaddr_in*)a->address;
    xtcp_info("[%p] added utp socket for fd %d for incoming connection %s:%d", s,
            ctxdata->sockfd, inet_ntoa(addr->sin_addr), addr->sin_port);


	return 0;
}

/*uint64 callback_on_firewall(utp_callback_arguments *a) {*/
	/*fprintf(stderr, "Firewall allowing inbound connection");*/
	/*return 0;*/
/*}*/

uint64 utp_on_read_cb(utp_callback_arguments *a) {
    utp_socket *s = a->socket;
    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
    sdata->readbuf = g_byte_array_append(sdata->readbuf, (unsigned char *)a->buf, a->len);
    utp_read_drained(s);

    xtcp_info("[%p] read in %lu bytes on %d", s, a->len, sdata->sockfd);

	return 0;
}

void utp_handle_icmp(utp_context *ctx, int sockfd) {
    xtcp_debug("received ICMP on socket %d", sockfd);
	while (1) {
		unsigned char vec_buf[4096], ancillary_buf[4096];
		struct iovec iov = { vec_buf, sizeof(vec_buf) };
		struct sockaddr_in remote;
		struct msghdr msg;
		ssize_t len;
		struct cmsghdr *cmsg;
		struct sock_extended_err *e;
		struct sockaddr *icmp_addr;
		struct sockaddr_in *icmp_sin;

		memset(&msg, 0, sizeof(msg));

		msg.msg_name = &remote;
		msg.msg_namelen = sizeof(remote);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = ancillary_buf;
		msg.msg_controllen = sizeof(ancillary_buf);

		len = recvmsg(sockfd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);

		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
            } else {
				xtcp_error("recvmsg returned %d", len);
            }
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_type != IP_RECVERR) {
				xtcp_debug("Unhandled errqueue type: %d", cmsg->cmsg_type);
				continue;
			}

			if (cmsg->cmsg_level != SOL_IP) {
				xtcp_debug("Unhandled errqueue level: %d", cmsg->cmsg_level);
				continue;
			}

			xtcp_debug("errqueue: IP_RECVERR, SOL_IP, len %zd", cmsg->cmsg_len);

			if (remote.sin_family != AF_INET) {
				xtcp_debug("Address family is %d, not AF_INET?  Ignoring", remote.sin_family);
				continue;
			}

			xtcp_debug("Remote host: %s:%d", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));

			e = (struct sock_extended_err *) CMSG_DATA(cmsg);

			if (!e) {
				xtcp_debug("errqueue: sock_extended_err is NULL?");
				continue;
			}

			if (e->ee_origin != SO_EE_ORIGIN_ICMP) {
				xtcp_debug("errqueue: Unexpected origin: %d", e->ee_origin);
				continue;
			}

			xtcp_debug("    ee_errno:  %d", e->ee_errno);
			xtcp_debug("    ee_origin: %d", e->ee_origin);
			xtcp_debug("    ee_type:   %d", e->ee_type);
			xtcp_debug("    ee_code:   %d", e->ee_code);
			xtcp_debug("    ee_info:   %d", e->ee_info);	// discovered MTU for EMSGSIZE errors
			xtcp_debug("    ee_data:   %d", e->ee_data);

			// "Node that caused the error"
			// "Node that generated the error"
			icmp_addr = (struct sockaddr *) SO_EE_OFFENDER(e);
			icmp_sin = (struct sockaddr_in *) icmp_addr;

			if (icmp_addr->sa_family != AF_INET) {
				xtcp_debug("ICMP's address family is %d, not AF_INET?", icmp_addr->sa_family);
				continue;
			}

			if (icmp_sin->sin_port != 0) {
				xtcp_debug("ICMP's 'port' is not 0?");
				continue;
			}

			/*xtcp_debug("msg_flags: %d", msg.msg_flags);*/
			/*if (o_xtcp_debug) {*/
				/*if (msg.msg_flags & MSG_TRUNC)		fprintf(stderr, " MSG_TRUNC");*/
				/*if (msg.msg_flags & MSG_CTRUNC)		fprintf(stderr, " MSG_CTRUNC");*/
				/*if (msg.msg_flags & MSG_EOR)		fprintf(stderr, " MSG_EOR");*/
				/*if (msg.msg_flags & MSG_OOB)		fprintf(stderr, " MSG_OOB");*/
				/*if (msg.msg_flags & MSG_ERRQUEUE)	fprintf(stderr, " MSG_ERRQUEUE");*/
				/*fprintf(stderr, "");*/
			/*}*/

			/*if (o_xtcp_debug >= 3)*/
				/*hexdump(vec_buf, len);*/

			if (e->ee_type == 3 && e->ee_code == 4) {
				xtcp_debug("ICMP type 3, code 4: Fragmentation error, discovered MTU %d", e->ee_info);
				utp_process_icmp_fragmentation(ctx, vec_buf, len, (struct sockaddr *)&remote, sizeof(remote), e->ee_info);
			}
			else {
				xtcp_debug("ICMP type %d, code %d", e->ee_type, e->ee_code);
				utp_process_icmp_error(ctx, vec_buf, len, (struct sockaddr *)&remote, sizeof(remote));
			}
		}
	}
}



int utp_read_context(utp_context *ctx, utp_context_data_t *ctxdata) {
    assert(ctx && ctxdata);

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
    if(sockfd < 0) {
        xtcp_error("error creating sockfd");
        return sockfd;
    }

    utp_context *ctx = utp_create_context(sockfd, (type & SOCK_NONBLOCK));
    if(!ctx) {
        xtcp_error("could not create context");
        return -1;
    }

    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    if(!ctxdata) {
        xtcp_error("no ctxdata for context %p on sockfd %d", ctx, sockfd);
        return -1;
    }

    int on = 1;
    setsockopt(sockfd, SOL_IP, IP_RECVERR, &on, sizeof(on));

    /* add socket to context mapping */
    g_hash_table_insert(global_data.sockfd_to_context, GINT_TO_POINTER(ctxdata->sockfd), ctx); 
    g_hash_table_insert(global_data.timerfd_to_context, GINT_TO_POINTER(ctxdata->timerfd), ctx); 

    xtcp_info("created socket %d (timer %d) which is %sblocking", 
            ctxdata->sockfd, ctxdata->timerfd, (type & SOCK_NONBLOCK) ? "non-" : "");

    return sockfd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    xtcp_debug("bind on socket %d", sockfd);

    utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
            GINT_TO_POINTER(sockfd));
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
    if(!g_hash_table_lookup(global_data.sockfd_to_context, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.listen(sockfd, backlog);
    }
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    xtcp_debug("accept on socket %d", sockfd);

    utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
            GINT_TO_POINTER(sockfd));
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
    while(!ctxdata->nonblock && g_queue_get_length(ctxdata->socketq) == 0) {
        if(utp_read_context(ctx, ctxdata) < 0) {
            return -1;
        }
    }

    /* get a socket from the queue, if we don't have one return block */
    utp_socket *s = (utp_socket *)g_queue_pop_head(ctxdata->socketq);
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

    g_hash_table_insert(global_data.sockfd_to_socket, GINT_TO_POINTER(newsockfd), s);

    xtcp_info("added socket %d for socket %p", newsockfd, s);

    return newsockfd;
}

int connect(int sockfd, const struct sockaddr *address, socklen_t address_len) {
    xtcp_debug("connect on socket %d", sockfd);
    
    utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
            GINT_TO_POINTER(sockfd));
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
    sdata->readbuf = g_byte_array_new();
    sdata->sockfd = sockfd;
    utp_set_userdata(s, sdata);

    utp_connect(s, address, address_len);
    g_hash_table_insert(global_data.sockfd_to_socket, GINT_TO_POINTER(sockfd), s);

    // TODO if this is a blocking socket, wait until we get a response to return
    if(ctxdata->nonblock) {
        errno = EINPROGRESS;
        return -1;
    } 

    return 0;
}

ssize_t xtcp_send(int sockfd, const void *buf, size_t len, int flags) {
    xtcp_debug("send %d bytes on socket %d", len, sockfd);

    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket, 
            GINT_TO_POINTER(sockfd));
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
        struct epoll_event ev;
        ev.data.fd = sockfd;
        ev.events = EPOLLIN;

        global_data.libc.epoll_ctl(ctxdata->epollfd, EPOLL_CTL_MOD, sockfd, &ev);

        sdata->writeable = 0;
        errno = EWOULDBLOCK;
        return -1;
    }

    return bytes;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    return xtcp_send(sockfd, buf, len, flags);
}

ssize_t xtcp_recv(int sockfd, void *buf, size_t len, int flags) {
    xtcp_debug("recv %d bytes on socket %d", len, sockfd);

    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket, 
            GINT_TO_POINTER(sockfd));
    if(!s) {
        return global_data.libc.recv(sockfd, buf, len, flags);
    }

    utp_context *ctx = utp_get_context(s);
    utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);

    /* if closed return 0 so application knows */
    if(sdata->eof || sdata->closed) {
        return 0;
    }

    /* if the socket is blocking, wait until we have enough bytes to fill the buffer */
    while(!ctxdata->nonblock && sdata->readbuf->len < len) {
        if(utp_read_context(ctx, ctxdata) < 0) {
            return -1;
        }
    }

    len = MIN(len, sdata->readbuf->len);
    if(len == 0) {
        errno = EWOULDBLOCK;
        return -1;
    }

    memcpy(buf, sdata->readbuf->data, len);
    sdata->readbuf = g_byte_array_remove_range(sdata->readbuf, 0, len);

    return len;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    return xtcp_recv(sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    /*xtcp_debug("write %d bytes on fd %d", count, fd);*/
    
    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket, 
            GINT_TO_POINTER(fd));
    if(!s) {
        return global_data.libc.write(fd, buf, count);
    }

    return xtcp_send(fd, buf, count, 0);
}

ssize_t read(int fd, void *buf, size_t count) {
    xtcp_debug("read %d bytes on fd %d", count, fd);

    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket, 
            GINT_TO_POINTER(fd));
    if(!s) {
        return global_data.libc.read(fd, buf, count);
    }

    return xtcp_recv(fd, buf, count, 0);
}

int close(int fd) {
    utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
            GINT_TO_POINTER(fd));
    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket,
            GINT_TO_POINTER(fd));
    if(!s) {
        /*xtcp_debug("closing fd %d", fd);*/
        return global_data.libc.close(fd);
    }

    xtcp_info("closing socket %d", fd);

    utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
    sdata->closed = 1;

    if(ctx) {
        utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
        ctxdata->closed = 1;
    }

    utp_close(s);

    return 0;
}

/*
 * Poll/Select functions
 */
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    xtcp_debug("epoll_ctl epfd %d op %d fd %d events %u", epfd, op, fd,
            (event ? event->events : 0));

    utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context,
            GINT_TO_POINTER(fd));
    utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket,
            GINT_TO_POINTER(fd));

    if(!ctx && !s) {
        return global_data.libc.epoll_ctl(epfd, op, fd, event);
    }

    struct epoll_event ev;

    /* if we're adding a context sockfd, also add the timerfd */
    if(ctx && op == EPOLL_CTL_ADD) {
        utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
        ev.data.fd = ctxdata->timerfd;
        ev.events = EPOLLIN | EPOLLET;
        global_data.libc.epoll_ctl(epfd, EPOLL_CTL_ADD, ctxdata->timerfd, &ev);
    }

    ev.data.fd = fd;
    ev.events = EPOLLIN;
    return global_data.libc.epoll_ctl(epfd, op, fd, &ev);
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

        xtcp_debug("fd %d has events %u", fd, ev);

        if(g_hash_table_lookup(global_data.sockfd_to_context, GINT_TO_POINTER(fd))) {
            utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
                    GINT_TO_POINTER(fd));
            utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
            if(!ctxdata) {
                xtcp_error("no context data for socket %d", fd);
                return -1;
            }

            xtcp_debug("have event %d for context %d", ev, fd);

            if(ev & EPOLLERR) {
                utp_handle_icmp(ctx, ctxdata->sockfd);
            } else if(ev & EPOLLIN) {
                if(utp_read_context(ctx, ctxdata) < 0) {
                    xtcp_warning("problems reading from context %p on %d", ctx, fd);
                }

                if(!ctxdata->closed && g_queue_get_length(ctxdata->socketq) > 0) {
                    events[nfds].data.fd = fd;
                    events[nfds].events = EPOLLIN;
                    nfds++;
                }
            }
        } else if(g_hash_table_lookup(global_data.timerfd_to_context, GINT_TO_POINTER(fd))) {
            uint64_t val;
            read(fd, &val, 8);

            utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.timerfd_to_context, 
                    GINT_TO_POINTER(fd));
            utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
            xtcp_info("check timeouts for ctx %p on %d", ctx, ctxdata->sockfd);
            utp_check_timeouts(ctx);
        } else if(!g_hash_table_lookup(global_data.sockfd_to_socket, GINT_TO_POINTER(fd))) {
            memcpy(&events[nfds], &evs[i], sizeof(struct epoll_event));
            nfds++;
        }
    }

    GList *iter = g_hash_table_get_values(global_data.sockfd_to_socket);
    while(iter) {
        /*utp_socket *s = (utp_socket *)sockets[idx];*/
        utp_socket *s = (utp_socket *)iter->data;
        utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
        if(!sdata) {
            xtcp_error("no utp socket for socket %p", s);
            return -1;
        }

        int ev = 0;
        if(sdata->eof) {
            ev |= EPOLLIN;
        } else if(sdata->connected) {
            if(sdata->readbuf->len > 0) {
                ev |= EPOLLIN;
            }
            if(sdata->writeable) {
                ev |= EPOLLOUT;
            }
        }

        xtcp_debug("socket %d has event %d [%d/%d]", sdata->sockfd, ev, 
                sdata->eof, sdata->closed);
        if(!sdata->closed && ev) {
            events[nfds].data.fd = sdata->sockfd;
            events[nfds].events = ev;
            nfds++;
        }

        /*idx++;*/
        iter = iter->next;
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

        utp_context *ctx = (utp_context *)g_hash_table_lookup(global_data.sockfd_to_context, 
                GINT_TO_POINTER(fd));
        if(ctx) {
            utp_context_data_t *ctxdata = (utp_context_data_t *)utp_context_get_userdata(ctx);
            if(!ctxdata) {
                xtcp_error("no context data for socket %d", fd);
                return -1;
            }

            utp_read_context(ctx, ctxdata);

            if(g_queue_get_length(ctxdata->socketq) > 0 && readfds && !FD_ISSET(fd, readfds)) {
                xtcp_debug("socket to accept, marking %d as readable", fd);
                FD_SET(fd, readfds);
                ret++;
            }

            utp_check_timeouts(ctx);
        }

        utp_socket *s = (utp_socket *)g_hash_table_lookup(global_data.sockfd_to_socket, GINT_TO_POINTER(fd));
        if(s) {
            utp_socket_data_t *sdata = (utp_socket_data_t *)utp_get_userdata(s);
            if(!sdata) {
                xtcp_error("no utp socket for socket %d", fd);
                return -1;
            }

            if(readfds && FD_ISSET(fd, readfds)) {
                FD_CLR(fd, readfds);
                ret--;
                if(sdata->readbuf->len > 0) {
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

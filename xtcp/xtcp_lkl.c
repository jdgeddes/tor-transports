#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <glib.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <lkl.h>
#include <lkl_host.h>
#include "xlate.h"

#include "xtcp.h"
#include "xtcp_util.h"

static void init() __attribute__((constructor));

typedef struct libc_func_s {
    SocketFunc socket;
    IoctlFunc ioctl;
    SetSockoptFunc setsockopt;
    GetSockoptFunc getsockopt;
    BindFunc bind;
    ListenFunc listen;
    AcceptFunc accept;
    WriteFunc write;
    ReadFunc read;
    ConnectFunc connect;
    SendFunc send;
    RecvFunc recv;
    CloseFunc close;
    EpollCreateFunc epoll_create;
    EpollCtlFunc epoll_ctl;
    EpollWaitFunc epoll_wait;
    SelectFunc select;
    TimerFdCreateFunc timerfd_create;
} libc_func_t;


typedef struct global_data_s {
    libc_func_t libc;
    int initialized;
    GHashTable *lkl_sockets;
    GHashTable *lkl_epolld;
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

static int lkl_call(int nr, int args, ...) {
	long params[6];
	va_list vl;
	int i;

	va_start(vl, args);
	for (i = 0; i < args; i++)
		params[i] = va_arg(vl, long);
	va_end(vl);

	return lkl_set_errno(lkl_syscall(nr, params));
}

static void lkl_print(const char *str, int len) {
    char *s = (char *)malloc(sizeof(char) * len);
    strncpy(s, str, len - 1);
    s[len - 1] = 0;
    xtcp_info("[LKL] %s", s);
    free(s);
}

in_addr_t get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;

    if(getifaddrs(&ifaddr) < 0) {
        xtcp_warning("error calling getifaddrs: %s", strerror(errno));
        return -1;
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            return sin->sin_addr.s_addr;
        }
    }

    return INADDR_NONE;
}

int lkl_create_device(char *hostname) {
    struct lkl_netdev *nd = NULL;
    int nd_id;

    GString *interface = g_string_new("");
    g_string_printf(interface, "%s-eth0", hostname);

    gchar *devname = g_string_free(interface, FALSE);

    /* setup device */
    nd = lkl_netdev_tap_create(devname);
    if(!nd) {
        xtcp_error("could not create TAP device %s", devname);
        return -1;
    }
    xtcp_info("added device for %s", devname);
    free(devname);

    nd_id = lkl_netdev_add(nd, NULL);
    if(nd_id < 0) {
        xtcp_error("failed to add netdev: %s", lkl_strerror(nd_id));
        return -1;
    }

    return nd_id;
}

int lkl_setup_device(int nd_id,  in_addr_t ip) {
    int ret, nd_ifindex;

    nd_ifindex = lkl_netdev_get_ifindex(nd_id);
    if(!nd_ifindex) {
        xtcp_error("failed to get ifindex for netdev id %d: %s", nd_id, lkl_strerror(nd_ifindex));
        return -1;

    }
    lkl_if_up(nd_ifindex);

    int netmask_len = 24;
    ret = lkl_if_set_ipv4(nd_ifindex, ip, netmask_len);
    if(ret < 0) {
        xtcp_error("failed to set IPv4 address: %s", lkl_strerror(ret));
        return ret;
    }

    in_addr_t gateway = inet_addr("192.168.14.1");
    ret = lkl_set_ipv4_gateway(gateway);
    if(ret < 0) {
        xtcp_error("failed to set IPv4 gateway: %s", lkl_strerror(ret));
        /*return -1;*/
    }

    return 0;
}

void init_lib() {
    if(global_data.initialized) {
        xtcp_info("already initialized");
        /*return;*/
    }

    xtcp_info("initializing LKL xTCP library");

    SETSYM_OR_FAIL(socket);
    SETSYM_OR_FAIL(ioctl);
    SETSYM_OR_FAIL(bind);
    SETSYM_OR_FAIL(listen);
    SETSYM_OR_FAIL(accept);
    SETSYM_OR_FAIL(write);
    SETSYM_OR_FAIL(read);
    SETSYM_OR_FAIL(connect);
    SETSYM_OR_FAIL(send);
    SETSYM_OR_FAIL(recv);
    SETSYM_OR_FAIL(close);
    SETSYM_OR_FAIL(epoll_create);
    SETSYM_OR_FAIL(epoll_ctl);
    SETSYM_OR_FAIL(epoll_wait);
    SETSYM_OR_FAIL(select);
    SETSYM_OR_FAIL(timerfd_create);

    global_data.lkl_sockets = g_hash_table_new(g_direct_hash, g_direct_equal);
    global_data.lkl_epolld = g_hash_table_new(g_direct_hash, g_direct_equal);

    char *lkl_kernel_loaded = getenv("LKL_KERNEL_LOADED");

    lkl_host_ops.print = lkl_print;

    in_addr_t ip;
    int ret;

    if(!lkl_kernel_loaded) {
        int devid = 0;

        if(!getenv("SHADOW_SPAWNED")) {
            devid = lkl_create_device("lkl");
            if(devid < 0) {
                xtcp_error("error creating LKL TAP device: %s", lkl_strerror(errno));
                return;
            }
        }

        /* start kernel */
        ret = lkl_start_kernel(&lkl_host_ops, 64 * 1024 * 1024, "");
        if(ret) {
            xtcp_error("can't start kernel: %s", lkl_strerror(ret));
            return;
        }

        xtcp_info("kernel started, bring up devices");

        /* bring up localhost */
        lkl_if_up(1);

        if(devid >= 0) {
            xtcp_info("setting IP address for dev %d", devid);

            ip = inet_addr("192.168.14.2");
            if(lkl_setup_device(devid, ip) < 0) {
                xtcp_error("error setting up LKL device: %s", lkl_strerror(errno));
                return;
            }
        }


        /* fillup FDs up to LKL_FD_OFFSET */
        ret = lkl_sys_mknod("/dev_null", LKL_S_IFCHR | 0600, LKL_MKDEV(1, 3));
        int dev_null = lkl_sys_open("/dev_null", LKL_O_RDONLY, 0);
        if (dev_null < 0) {
            xtcp_error("failed to open /dev/null: %s", lkl_strerror(dev_null));
            return;
        }

        int i;
        for (i = 1; i < 512; i++) {
            lkl_sys_dup(dev_null);
        }

        setenv("LKL_KERNEL_LOADED", "TRUE", 1);
    } else {
        char hostname[256];

        ip = get_local_ip();
        if(ip == INADDR_NONE) {
            xtcp_error("could not get my IP: %s", strerror(errno));
            return;
        }

        if(gethostname(hostname, sizeof(hostname)) < 0) {
            xtcp_error("could not get my hostname: %s", strerror(errno));
            return;
        }

        int devid = lkl_create_device(hostname);
        if(devid < 0) {
            xtcp_error("error creating device for %s: %s", hostname, lkl_strerror(errno));
            return;
        }

        if(lkl_setup_device(devid, ip) < 0) {
            xtcp_error("error setting up device for %s: %s", hostname, lkl_strerror(errno));
            return;
        }
    }


    global_data.initialized = TRUE;

    xtcp_info("initialized all interposed functions");
}

void init() {
    if(!getenv("SHADOW_SPANWED")) {
       init_lib();
    }
}

int socket(int domain, int type, int protocol) {
    xtcp_info("socket domain %d type %d proto %d", domain, type, protocol);
    if(!(type & SOCK_STREAM)) {
        return global_data.libc.socket(domain, type, protocol);
    }

    int sockfd = lkl_call(__lkl__NR_socket, 3, domain, type, protocol);
    g_hash_table_insert(global_data.lkl_sockets, GINT_TO_POINTER(sockfd),
            GINT_TO_POINTER(TRUE));

    xtcp_info("created LKL socket %d (%s)", sockfd, strerror(errno));

    return sockfd;
}

int ioctl(int fd, unsigned req, ...) {
    xtcp_info("ioctl fd %d", fd);

    va_list vl;
    long arg;

    va_start(vl, req);
    arg = va_arg(vl, long);
    va_end(vl);

    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.ioctl(fd, req, arg);
    }
    xtcp_info("lkl ioctl %d", fd);
    return lkl_call(__lkl__NR_ioctl, 3, fd, lkl_ioctl_req_xlate(req), arg);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.setsockopt(fd, level, optname, optval, optlen);
    }
    xtcp_info("setsockopt %d", fd);
    return lkl_call(__lkl__NR_setsockopt, 5, fd, level, optname, optval, optlen);
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.getsockopt(fd, level, optname, optval, optlen);
    }
    xtcp_info("getsockopt %d", fd);
    return lkl_call(__lkl__NR_getsockopt, 5, fd, level, optname, optval, optlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.bind(sockfd, addr, addrlen);
    }
    xtcp_info("bind %d", sockfd);
    return lkl_call(__lkl__NR_bind, 3, sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.listen(sockfd, backlog);
    }
    xtcp_info("listen %d", sockfd);
    return lkl_call(__lkl__NR_listen, 2, sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.accept(sockfd, addr, addrlen);
    }

    int newsockfd = lkl_call(__lkl__NR_accept, 3, sockfd, addr, addrlen);
    g_hash_table_insert(global_data.lkl_sockets, GINT_TO_POINTER(newsockfd), GINT_TO_POINTER(TRUE));

    xtcp_info("accept %d on %d", newsockfd, sockfd);

    return newsockfd;
}

int connect(int sockfd, const struct sockaddr *address, socklen_t address_len) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.connect(sockfd, address, address_len);
    }
    xtcp_info("connect %d", sockfd);
    return lkl_call(__lkl__NR_connect, 3, sockfd, address, address_len);
}

/*void print_tcp_info(int sockfd) {*/
    /*struct tcp_info tcp_info;*/
    /*socklen_t tcp_info_len = sizeof(tcp_info);*/

    /*if(getsockopt(sockfd, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_len) == 0) {*/
        /*xtcp_info("sockfd %d cwnd %u ssthresh %u rtt %u lost %u retrans %u", sockfd, */
                /*tcp_info.tcpi_snd_cwnd, tcp_info.tcpi_snd_ssthresh,*/
                /*tcp_info.tcpi_rtt, tcp_info.tcpi_lost, tcp_info.tcpi_retrans);*/
    /*}*/
/*}*/

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.send(sockfd, buf, len, flags);
    }
    xtcp_info("send %d", sockfd);
    return lkl_call(__lkl__NR_send, 4, sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {
        return global_data.libc.recv(sockfd, buf, len, flags);
    }
    xtcp_info("recv %d", sockfd);
    return lkl_call(__lkl__NR_recv, 4, sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.write(fd, buf, count);
    }
    /*xtcp_info("write %d bytes on %d", count, fd);*/
    return lkl_call(__lkl__NR_write, 3, fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.read(fd, buf, count);
    }
    return lkl_call(__lkl__NR_read, 3, fd, buf, count);
}

int close(int fd) {
    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.close(fd);
    }
    g_hash_table_remove(global_data.lkl_sockets, GINT_TO_POINTER(fd));
    return lkl_call(__lkl__NR_close, 1, fd);
}

int epoll_create(int size) {
    int localfd = global_data.libc.epoll_create(size);
    int lklfd = lkl_call(__lkl__NR_epoll_create, 1, size);
    xtcp_info("creating local epoll %d and LKL %d", localfd, lklfd);
    g_hash_table_insert(global_data.lkl_epolld, GINT_TO_POINTER(localfd), GINT_TO_POINTER(lklfd));
    return localfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    xtcp_info("epoll ctl epfd %d op %d fd %d", epfd, op, fd);

    if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(fd))) {
        return global_data.libc.epoll_ctl(epfd, op, fd, event);
    }

    int lkl_epfd = GPOINTER_TO_INT(g_hash_table_lookup(global_data.lkl_epolld, GINT_TO_POINTER(epfd)));
    if(!lkl_epfd) {
        xtcp_warning("no LKL epfd for %d", epfd);
        return -1;
    }

    return lkl_call(__lkl__NR_epoll_ctl, 4, lkl_epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    int lkl_epfd = GPOINTER_TO_INT(g_hash_table_lookup(global_data.lkl_epolld, GINT_TO_POINTER(epfd)));

    if(!lkl_epfd) {
        return global_data.libc.epoll_wait(epfd, events, maxevents, timeout);
    }

    xtcp_info("epoll wait %d/%d (%d)", epfd, lkl_epfd, timeout);

    int nevents = 0;
    int nlocal = 0;
    int nlkl = 0;

    if(timeout == -1) {
        while(!nlocal && !nlkl) {
            nlocal = global_data.libc.epoll_wait(epfd, events, maxevents, 0);
            nlkl =  lkl_call(__lkl__NR_epoll_wait, 4, lkl_epfd, &(events[nlocal]), maxevents - nlocal, 0);
        }
    } else {
        nlocal = global_data.libc.epoll_wait(epfd, events, maxevents, 0);
        nlkl =  lkl_call(__lkl__NR_epoll_wait, 4, lkl_epfd, &(events[nlocal]), maxevents - nlocal, 0);
    }
    nevents = nlocal + nlkl;

    xtcp_info("returning %d events (%d local %d LKL)", nevents, nlocal, nlkl);

    return nevents;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *expectfds, struct timeval *timeout) {
    /*if(!g_hash_table_lookup(global_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {*/
        /*return global_data.libc.select(nfds, readfds, writefds, expectfds, timeout);*/
    /*}*/
    xtcp_info("select %d", nfds);
    return lkl_call(__lkl__NR_select, 5, nfds, readfds, writefds, expectfds, timeout);
}

int timerfd_create(int clockid, int flags) {
    int fd = global_data.libc.timerfd_create(clockid, flags);
    xtcp_info("timerfd_create fd %d", fd);   
    return fd;
}

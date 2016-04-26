#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <glib.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>

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
    GQueue *devices;
} global_data_t;

typedef struct instance_data_s {
    gint device_index;
    GHashTable *lkl_sockets;
    GHashTable *lkl_epolld;
} instance_data_t;

global_data_t global_data;
global_data_t *global_data_pointer = &global_data;
int global_data_size = sizeof(global_data);

instance_data_t instance_data;
instance_data_t *instance_data_pointer = &instance_data;
int instance_data_size = sizeof(instance_data);

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

#define IS_LKL_SOCKET(fd) (instance_data.lkl_sockets && \
        g_hash_table_lookup(instance_data.lkl_sockets, GINT_TO_POINTER(fd)))

#define IS_LKL_EPOLL(fd) (instance_data.lkl_epolld && \
g_hash_table_lookup(instance_data.lkl_epolld, GINT_TO_POINTER(fd)))


static int lkl_call(int nr, int args, ...) {
    long params[6];
    va_list vl;
    int i;

    va_start(vl, args);
    for(i = 0; i < args; i++) {
        params[i] = va_arg(vl, long);
    }
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

int get_local_addresses(in_addr_t *ip, unsigned char *mac) {
    int s, ret;
    struct ifreq ifr;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(s < 0) {
        xtcp_error("error opening socket: %s", strerror(errno));
        return s;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, "eth0");

    ret = ioctl(s, SIOCGIFADDR, &ifr);
    if(ret < 0) {
        xtcp_error("error getting IP address: %s", strerror(errno));
        return ret;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)(&ifr.ifr_addr);
    *ip = sin->sin_addr.s_addr;

    ret = ioctl(s, SIOCGIFHWADDR, &ifr);
    if(ret < 0) {
        xtcp_error("error getting MAC address: %s", strerror(errno));
        return ret;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 8);

    return 0;
}

int initialize_library(int argc, char *argv[]) {
    xtcp_message("initializing LKL library");

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

    int ndevs = 1;
    int kernel_memory = 64 * 1024 * 1024;

    if(argc > 0) {
        ndevs = atoi(argv[0]);
    }
    if(argc > 1) {
        kernel_memory = atoi(argv[1]);
    }

    struct lkl_netdev *nd = NULL;
    int i, ret, nd_id, nd_ifindex;

    xtcp_info("creating %d devices", ndevs);

    for(i = 0; i < ndevs; i++) {
        char devname[32];
        sprintf(devname, "lkl%d", i);

        nd = lkl_netdev_tap_create(devname);
        if(!nd) {
            xtcp_error("error creating device %s: %s", devname, lkl_strerror(errno));
            return -1;
        }

        nd_id = lkl_netdev_add(nd, NULL);
        if(nd_id < 0) {
            xtcp_error("error adding device: %s", lkl_strerror(errno));
            return -1;
        }
    }

    xtcp_info("starting LKL kernel");

    /* start kernel */
    lkl_host_ops.print = lkl_print;

    ret = lkl_start_kernel(&lkl_host_ops,  kernel_memory, "");
    if(ret) {
        xtcp_error("can't start kernel: %s", lkl_strerror(ret));
        return -1;
    }

    /* bring up localhost */
    lkl_if_up(1);

    global_data.devices = g_queue_new();

    /* bring up all the devices and add them to queue */
    for(i = 0; i < ndevs; i++) {
        nd_ifindex = lkl_netdev_get_ifindex(i);
        if(nd_ifindex < 0) {
            xtcp_error("error getting nfindex for dev %d: %s", i, lkl_strerror(nd_ifindex));
            return -1;
        }

        g_queue_push_tail(global_data.devices, GINT_TO_POINTER(nd_ifindex));
    }

    /* fillup FDs up to LKL_FD_OFFSET */
    ret = lkl_sys_mknod("/dev_null", LKL_S_IFCHR | 0600, LKL_MKDEV(1, 3));
    int dev_null = lkl_sys_open("/dev_null", LKL_O_RDONLY, 0);
    if (dev_null < 0) {
        xtcp_error("failed to open /dev/null: %s", lkl_strerror(dev_null));
        return -1;
    }

    for (i = 1; i < 512; i++) {
        lkl_sys_dup(dev_null);
    }

    return 0;
}

int new_library_instance() {
    xtcp_info("new LKL instance");

    instance_data.lkl_sockets = g_hash_table_new(g_direct_hash, g_direct_equal);
    instance_data.lkl_epolld = g_hash_table_new(g_direct_hash, g_direct_equal);

    if(g_queue_get_length(global_data.devices) == 0) {
        xtcp_error("no more devices for LKL instance");
        return -1;
    }

    instance_data.device_index = GPOINTER_TO_INT(g_queue_pop_head(global_data.devices));
    lkl_if_up(instance_data.device_index);

    in_addr_t ip;
    unsigned char mac[8];
    int ret;

    get_local_addresses(&ip, mac);

    char ipStringBuffer[256];
    const char *ipString = inet_ntop(AF_INET, &ip, ipStringBuffer, sizeof(ipStringBuffer)); 
    xtcp_info("setting IP of device %d to %s (%lu [%lu])", instance_data.device_index,
            ipString, ip, inet_addr("11.0.0.1"));


    ret = lkl_if_set_ipv4(instance_data.device_index, ip, 24);
    if(ret < 0) {
        xtcp_error("could not set IPv4 address for index %d: %s", instance_data.device_index, 
                lkl_strerror(ret));
        return -1;
    }

    /*ret = lkl_set_ipv4_gateway(inet_addr("11.1.0.1"));*/
    /*if(ret < 0) {*/
        /*xtcp_error("could not set gateway: %s", lkl_strerror(ret));*/
        /*return -1;*/
    /*}*/

    return 0;
}

void init() {
    char *inshadow = getenv("SHADOW_SPAWNED");

    xtcp_info("init xTCP LKL library (in shadow %s)", (inshadow ? inshadow : "NULL"));
    if(!inshadow) {
        initialize_library(0, NULL);
        new_library_instance();
    }
}

int socket(int domain, int type, int protocol) {
    xtcp_info("socket domain %d type %d proto %d", domain, type, protocol);
    if(!(type & SOCK_STREAM)) {
        return global_data.libc.socket(domain, type, protocol);
    }

    int sockfd = lkl_call(__lkl__NR_socket, 3, domain, type, protocol);
    g_hash_table_insert(instance_data.lkl_sockets, GINT_TO_POINTER(sockfd),
            GINT_TO_POINTER(TRUE));

    xtcp_info("created LKL socket %d (%s)", sockfd, strerror(errno));

    return sockfd;
}

int ioctl(int fd, unsigned long int req, ...) {
    xtcp_info("ioctl fd %d", fd);

    va_list vl;
    long arg;

    va_start(vl, req);
    arg = va_arg(vl, long);
    va_end(vl);

    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.ioctl(fd, req, arg);
    }
    xtcp_info("lkl ioctl %d", fd);
    return lkl_call(__lkl__NR_ioctl, 3, fd, lkl_ioctl_req_xlate(req), arg);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.setsockopt(fd, level, optname, optval, optlen);
    }
    xtcp_info("setsockopt %d", fd);
    return lkl_call(__lkl__NR_setsockopt, 5, fd, level, optname, optval, optlen);
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.getsockopt(fd, level, optname, optval, optlen);
    }
    xtcp_info("getsockopt %d", fd);
    return lkl_call(__lkl__NR_getsockopt, 5, fd, level, optname, optval, optlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(!IS_LKL_SOCKET(sockfd)) {
        return global_data.libc.bind(sockfd, addr, addrlen);
    }
    xtcp_info("bind %d", sockfd);
    return lkl_call(__lkl__NR_bind, 3, sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
    if(!IS_LKL_SOCKET(sockfd)) {
        return global_data.libc.listen(sockfd, backlog);
    }
    xtcp_info("listen %d", sockfd);
    return lkl_call(__lkl__NR_listen, 2, sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if(!IS_LKL_SOCKET(sockfd)) {
        return global_data.libc.accept(sockfd, addr, addrlen);
    }

    int newsockfd = lkl_call(__lkl__NR_accept, 3, sockfd, addr, addrlen);
    g_hash_table_insert(instance_data.lkl_sockets, GINT_TO_POINTER(newsockfd), GINT_TO_POINTER(TRUE));

    xtcp_info("accept %d on %d", newsockfd, sockfd);

    return newsockfd;
}

int connect(int sockfd, const struct sockaddr *address, socklen_t address_len) {
    if(!IS_LKL_SOCKET(sockfd)) {
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
    if(!IS_LKL_SOCKET(sockfd)) {
        return global_data.libc.send(sockfd, buf, len, flags);
    }
    xtcp_info("send %d", sockfd);
    return lkl_call(__lkl__NR_send, 4, sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    if(!IS_LKL_SOCKET(sockfd)) {
        return global_data.libc.recv(sockfd, buf, len, flags);
    }
    xtcp_info("recv %d", sockfd);
    return lkl_call(__lkl__NR_recv, 4, sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
    /*xtcp_info("write %d", fd);*/
    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.write(fd, buf, count);
    }
    /*xtcp_info("write %d bytes on %d", count, fd);*/
    return lkl_call(__lkl__NR_write, 3, fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {
    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.read(fd, buf, count);
    }
    return lkl_call(__lkl__NR_read, 3, fd, buf, count);
}

int close(int fd) {
    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.close(fd);
    }
    g_hash_table_remove(instance_data.lkl_sockets, GINT_TO_POINTER(fd));
    return lkl_call(__lkl__NR_close, 1, fd);
}

int epoll_create(int size) {
    int localfd = global_data.libc.epoll_create(size);
    int lklfd = lkl_call(__lkl__NR_epoll_create, 1, size);
    xtcp_info("creating local epoll %d and LKL %d", localfd, lklfd);
    g_hash_table_insert(instance_data.lkl_epolld, GINT_TO_POINTER(localfd), GINT_TO_POINTER(lklfd));
    return localfd;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    xtcp_info("epoll ctl epfd %d op %d fd %d", epfd, op, fd);

    if(!IS_LKL_SOCKET(fd)) {
        return global_data.libc.epoll_ctl(epfd, op, fd, event);
    }

    int lkl_epfd = GPOINTER_TO_INT(g_hash_table_lookup(instance_data.lkl_epolld, GINT_TO_POINTER(epfd)));
    if(!lkl_epfd) {
        xtcp_warning("no LKL epfd for %d", epfd);
        return -1;
    }

    return lkl_call(__lkl__NR_epoll_ctl, 4, lkl_epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {


    if(!IS_LKL_EPOLL(epfd)) {
        return global_data.libc.epoll_wait(epfd, events, maxevents, timeout);
    }

    int lkl_epfd = GPOINTER_TO_INT(g_hash_table_lookup(instance_data.lkl_epolld, GINT_TO_POINTER(epfd)));
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
    /*if(!g_hash_table_lookup(instance_data.lkl_sockets, GINT_TO_POINTER(sockfd))) {*/
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

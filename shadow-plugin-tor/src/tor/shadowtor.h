/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#ifndef SCALLION_H_
#define SCALLION_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <gmodule.h>
#include <glib/gprintf.h>

#include <event2/event.h>
#include <event2/event_struct.h>

#include "shd-library.h"

/* includes from Tor */
#undef NDEBUG
//#ifndef _GNU_SOURCE
//#define _GNU_SOURCE 1
//#endif
# ifndef __daddr_t_defined
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;
#  define __daddr_t_defined
# ifndef __u_char_defined
# endif
typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;
#  define __u_char_defined
# endif

#include "orconfig.h"
#include "or.h"
#include "util.h"
#include "address.h"
#include "compat_libevent.h"
#include "compat.h"
#include "container.h"
#include "ht.h"
#include "memarea.h"
#include "mempool.h"
#include "torlog.h"
#include "tortls.h"
#include "buffers.h"
#include "config.h"
#include "cpuworker.h"
#include "dirserv.h"
#include "dirvote.h"
#include "hibernate.h"
#include "rephist.h"
#include "router.h"
#include "routerparse.h"
#include "onion.h"
#include "control.h"
#include "networkstatus.h"
//#include "src/common/OpenBSD_malloc_Linux.h"
#include "dns.h"
#include "circuitlist.h"
#include "policies.h"
#include "geoip.h"
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <time.h>

/* externals from Tor */
extern void socket_accounting_lock();
extern void socket_accounting_unlock();
extern routerlist_t *router_get_routerlist(void);
extern struct event_base * tor_libevent_get_base(void);
extern void tor_cleanup(void);
extern void second_elapsed_callback(periodic_timer_t *timer, void *arg);
extern void refill_callback(periodic_timer_t *timer, void *arg);
extern int init_keys(void);
extern void init_cell_pool(void);
extern void connection_bucket_init(void);
extern int trusted_dirs_reload_certs(void);
extern int router_reload_router_list(void);
extern void directory_info_has_arrived(time_t now, int from_cache);
extern int tor_init(int argc, char *argv[]);
extern int sockmgr_thread_loop_once(int64_t* pause_time_out);

extern int n_sockets_open;
extern int global_write_bucket;
extern int stats_prev_global_write_bucket;
extern int global_read_bucket;
extern int stats_prev_global_read_bucket;
extern periodic_timer_t * second_timer;
extern periodic_timer_t * refill_timer;
extern smartlist_t * active_linked_connection_lst;
#ifdef SCALLION_NEWIDKEYNAME
#ifdef SCALLION_NEWCRYPTODEFS
extern crypto_pk_t * client_identitykey;
#else
extern crypto_pk_env_t * client_identitykey;
#endif
#endif
extern int called_loop_once;

enum cpuwstate {
	CPUW_NONE,
	CPUW_READTYPE, CPUW_READTAG, CPUW_READCHALLENGE, CPUW_PROCESS, CPUW_WRITERESPONSE,
	CPUW_V2_READ, CPUW_V2_PROCESS, CPUW_V2_WRITE, CPUW_V2_RESET,
	CPUW_DEAD,
};

/** The tag specifies which circuit this onionskin was from. */
#ifdef SCALLION_LOGVWITHSUFFIX /* >= tor-0.2.4.11 */
#define TAG_LEN 12
#else
#define TAG_LEN 10
#endif

#ifdef SCALLION_USEV2CPUWORKER
/** Magic numbers to make sure our cpuworker_requests don't grow any
 * mis-framing bugs. */
#define CPUWORKER_REQUEST_MAGIC 0xda4afeed
#define CPUWORKER_REPLY_MAGIC 0x5eedf00d

/** A request sent to a cpuworker. */
typedef struct cpuworker_request_t {
  /** Magic number; must be CPUWORKER_REQUEST_MAGIC. */
  uint32_t magic;
  /** Opaque tag to identify the job */
  uint8_t tag[TAG_LEN];
  /** Task code. Must be one of CPUWORKER_TASK_* */
  uint8_t task;

#ifdef SCALLION_USEV2CPUWORKERTIMING
  /** Flag: Are we timing this request? */
  unsigned timed : 1;
  /** If we're timing this request, when was it sent to the cpuworker? */
  struct timeval started_at;
#endif

  /** A create cell for the cpuworker to process. */
  create_cell_t create_cell;

  /* Turn the above into a tagged union if needed. */
} cpuworker_request_t;

/** A reply sent by a cpuworker. */
typedef struct cpuworker_reply_t {
  /** Magic number; must be CPUWORKER_REPLY_MAGIC. */
  uint32_t magic;
  /** Opaque tag to identify the job; matches the request's tag.*/
  uint8_t tag[TAG_LEN];
  /** True iff we got a successful request. */
  uint8_t success;

#ifdef SCALLION_USEV2CPUWORKERTIMING
  /** Are we timing this request? */
  unsigned int timed : 1;
  /** What handshake type was the request? (Used for timing) */
  uint16_t handshake_type;
  /** When did we send the request to the cpuworker? */
  struct timeval started_at;
  /** Once the cpuworker received the request, how many microseconds did it
   * take? (This shouldn't overflow; 4 billion micoseconds is over an hour,
   * and we'll never have an onion handshake that takes so long.) */
  uint32_t n_usec;
#endif

  /** Output of processing a create cell
   *
   * @{
   */
  /** The created cell to send back. */
  created_cell_t created_cell;
  /** The keys to use on this circuit. */
  uint8_t keys[CPATH_KEY_MATERIAL_LEN];
  /** Input to use for authenticating introduce1 cells. */
  uint8_t rend_auth_material[DIGEST_LEN];
} cpuworker_reply_t;

#define SCALLION_CPUWORKER_MAGIC1 0x0f5d4576
#define SCALLION_CPUWORKER_MAGIC2 0xdc251bf9
#define SCALLION_CPUWORKER_MAGIC3 0xe9ed3bcf

#define SCALLION_CPUWORKER_ASSERT(cpuw) g_assert(cpuw);\
		g_assert(cpuw->magic1==SCALLION_CPUWORKER_MAGIC1);\
		g_assert(cpuw->magic2==SCALLION_CPUWORKER_MAGIC2);\
		g_assert(cpuw->magic3==SCALLION_CPUWORKER_MAGIC3)

typedef struct vtor_cpuworker_s {
	uint32_t magic1;
	cpuworker_request_t req;
	uint32_t magic2;
	cpuworker_reply_t rpl;
	uint32_t magic3;
	size_t num_partial_bytes;
	enum cpuwstate state;
	int fd;
	server_onion_keys_t onion_keys;
	struct event read_event;
} vtor_cpuworker_t, *vtor_cpuworker_tp;
#else
/** How many bytes are sent from the cpuworker back to tor? */
#define LEN_ONION_RESPONSE (1+TAG_LEN+ONIONSKIN_REPLY_LEN+CPATH_KEY_MATERIAL_LEN)
typedef struct vtor_cpuworker_s {
  int fd;
  char question[ONIONSKIN_CHALLENGE_LEN];
  uint8_t question_type;
  char keys[CPATH_KEY_MATERIAL_LEN];
  char reply_to_proxy[ONIONSKIN_REPLY_LEN];
  char buf[LEN_ONION_RESPONSE];
  char tag[TAG_LEN];
#ifdef SCALLION_NEWCRYPTODEFS
  crypto_pk_t *onion_key;
  crypto_pk_t *last_onion_key;
#else
  crypto_pk_env_t *onion_key;
  crypto_pk_env_t *last_onion_key;
#endif
  struct event read_event;
  uint offset;
  enum cpuwstate state;
} vtor_cpuworker_t, *vtor_cpuworker_tp;
#endif

typedef struct vtor_logfile_s {
    struct logfile_t *next; /**< Next logfile_t in the linked list. */
    char *filename; /**< Filename to open. */
    int fd; /**< fd to receive log messages, or -1 for none. */
    int seems_dead; /**< Boolean: true if the stream seems to be kaput. */
    int needs_close; /**< Boolean: true if the stream gets closed on shutdown. */
    int is_temporary; /**< Boolean: close after initializing logging subsystem.*/
    int is_syslog; /**< Boolean: send messages to syslog. */
    log_callback callback; /**< If not NULL, send messages to this function. */
    log_severity_list_t *severities; /**< Which severity of messages should we
                                      * log for each log domain? */
} vtor_logfile_t, *vtor_logfile_tp;

typedef struct _ScallionTor ScallionTor;
struct _ScallionTor {
	int refillmsecs;
	GSList* cpuWorkers;
	ShadowFunctionTable* shadowlibFuncs;
};

typedef struct _ShadowTor ShadowTor;
struct _ShadowTor {
	in_addr_t ip;
	gchar ipstring[40];
	gchar hostname[128];
	guint consensusCounter;
	ScallionTor* stor;
	ShadowFunctionTable* shadowlibFuncs;
	gboolean opensslThreadSupport;
    gboolean libeventThreadSupport;
    gboolean libeventHasError;
};

extern ShadowTor shadowtor;
#undef log

typedef void (*GlobalCleanupFunc())();

ScallionTor* shadowtor_getPointer();

void shadowtorpreload_init(GModule* handle, gint nLocks);
void shadowtorpreload_clear();

ScallionTor* shadowtor_new(ShadowFunctionTable* shadowlibFuncs, gchar* hostname,
		gint torargc, gchar* torargv[]);
void shadowtor_notify(ScallionTor* stor);
void shadowtor_free(ScallionTor* stor);

#endif /* SCALLION_H_ */

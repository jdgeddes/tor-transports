/*
 * See LICENSE for licensing information
 */

#ifndef SHD_TGEN_H_
#define SHD_TGEN_H_

#include <glib.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <shadow-plugin-interface.h>

#include "shd-tgen-global-lock.h"
#include "shd-tgen-io.h"
#include "shd-tgen-timer.h"
#include "shd-tgen-pool.h"
#include "shd-tgen-peer.h"
#include "shd-tgen-server.h"
#include "shd-tgen-transport.h"
#include "shd-tgen-transfer.h"
#include "shd-tgen-action.h"
#include "shd-tgen-graph.h"
#include "shd-tgen-driver.h"

#if 1 /* #ifdef DEBUG */
#define TGEN_MAGIC 0xABBABAAB
#define TGEN_ASSERT(obj) g_assert(obj && (obj->magic == TGEN_MAGIC))
#else
#define TGEN_MAGIC 0
#define TGEN_ASSERT(obj)
#endif

extern ShadowLogFunc tgenLogFunc;

#define tgen_error(...)     if(tgenLogFunc){tgenLogFunc(SHADOW_LOG_LEVEL_ERROR, __FUNCTION__, __VA_ARGS__);}
#define tgen_critical(...)  if(tgenLogFunc){tgenLogFunc(SHADOW_LOG_LEVEL_CRITICAL, __FUNCTION__, __VA_ARGS__);}
#define tgen_warning(...)   if(tgenLogFunc){tgenLogFunc(SHADOW_LOG_LEVEL_WARNING, __FUNCTION__, __VA_ARGS__);}
#define tgen_message(...)   if(tgenLogFunc){tgenLogFunc(SHADOW_LOG_LEVEL_MESSAGE, __FUNCTION__, __VA_ARGS__);}
#define tgen_info(...)      if(tgenLogFunc){tgenLogFunc(SHADOW_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__);}
#define tgen_debug(...)     if(tgenLogFunc){tgenLogFunc(SHADOW_LOG_LEVEL_DEBUG, __FUNCTION__, __VA_ARGS__);}

#endif /* SHD_TGEN_H_ */

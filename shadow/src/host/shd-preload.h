/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#ifndef SHD_PRELOAD_H_
#define SHD_PRELOAD_H_

#include "shadow.h"

typedef struct _Preload Preload;
typedef gpointer PreloadState;

typedef void (*PreloadInitFunc)();

Preload* preload_new(const gchar* name, const gchar* path);
void preload_free(Preload* lib);

Preload* preload_getTemporaryCopy(Preload* lib);
void preload_registerResidentState(Preload* lib);

void preload_swapInState(Preload* lib, PreloadState state);
void preload_swapOutState(Preload* lib, PreloadState state);

ShadowPluginInitializeFunc preload_getInitFunc(Preload* lib);
PluginNewInstanceFunc preload_getNewFunc(Preload* lib);
PluginNotifyFunc preload_getFreeFunc(Preload* lib);
PluginNotifyFunc preload_getNotifyFunc(Preload* lib);

PreloadState preload_newDefaultState(Preload* lib);
void preload_freeState(Preload* lib, gpointer state);

GQuark* preload_getID(Preload* lib);
gboolean preload_isRegistered(Preload* lib);
const gchar* preload_getName(Preload* lib);
gpointer preload_getFunction(Preload *lib, gchar* functionName);

#endif /* SHD_PRELOAD_H_ */

/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#ifndef SHD_LOAD_PRELOAD_H_
#define SHD_LOAD_PRELOAD_H_

#include "shadow.h"

typedef struct _LoadPreloadAction LoadPreloadAction;

LoadPreloadAction* loadpreload_new(GString* name, GString* path);
void loadpreload_run(LoadPreloadAction* action);
void loadpreload_free(LoadPreloadAction* action);

#endif /* SHD_LOAD_PRELOAD_H_ */

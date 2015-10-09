/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#include "shadow.h"
#include "shd-action-internal.h"

struct _LoadPreloadAction {
    Action super;
    GString* name;
    GString* path;
    MAGIC_DECLARE;
};

RunnableFunctionTable loadpreload_functions = {
    (RunnableRunFunc) loadpreload_run,
    (RunnableFreeFunc) loadpreload_free,
    MAGIC_VALUE
};

LoadPreloadAction* loadpreload_new(GString* name, GString* path) {
    utility_assert(name && path);
    LoadPreloadAction* action = g_new0(LoadPreloadAction, 1);
    MAGIC_INIT(action);

    action_init(&(action->super), &loadpreload_functions);

    action->name = g_string_new(name->str);
    action->path = g_string_new(path->str);

    return action;
}

void loadpreload_run(LoadPreloadAction* action) {
    MAGIC_ASSERT(action);

    /* we need a copy of the library for every thread because each of
     * them needs a separate instance of all the plug-in state so it doesn't
     * overlap. We'll do this lazily while booting up applications, since that
     * event will be run by a worker. For now, we just track the default
     * original plug-in library, so the worker can copy it later.
     */
    Preload* lib = preload_new(action->name->str, action->path->str);
    worker_storePreload(lib);
}

void loadpreload_free(LoadPreloadAction* action) {
    MAGIC_ASSERT(action);

    if(action->name) {
        g_string_free(action->name, TRUE);
    }
    if(action->path) {
        g_string_free(action->path, TRUE);
    }

    MAGIC_CLEAR(action);
    g_free(action);
}

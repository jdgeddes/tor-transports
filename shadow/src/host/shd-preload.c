/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */

#include <unistd.h>
#include <glib/gstdio.h>

#include "shadow.h"

#define PRELOADINITSYMBOL "init_lib"
#define PRELOADGLOBALSSYMBOL "global_data"
#define PRELOADGLOBALSSIZESYMBOL "global_data_size"
#define PRELOADGLOBALSPOINTERSYMBOL "global_data_pointer"

struct _Preload {
    GQuark id;

    GString* name;
    GString* path;
    GModule* handle;
    gboolean isTemporary;

    PreloadInitFunc init;

    gsize residentStateSize;
    gpointer residentStatePointer;
    gpointer residentState;
    PreloadState defaultState;

    gboolean isRegisterred;
    /*
     * TRUE from when we've called into preload library code until the call completes.
     * Note that the preload library may get back into shadow code during execution, by
     * calling one of the shadowlib functions or calling a function that we
     * intercept. isShadowContext distinguishes this.
     */
    gboolean isExecuting;

    MAGIC_DECLARE;
};

static GString* _preload_getTemporaryFilePath(gchar* originalPath) {
    /* get the basename of the real preload library and create a temp file template */
    gchar* basename = g_path_get_basename(originalPath);
    GString* templateBuffer = g_string_new(basename);
    g_free(basename);

    templateBuffer = g_string_prepend(templateBuffer, "XXXXXX-");
    gchar* template = g_string_free(templateBuffer, FALSE);

    /* try to open the templated file, checking for errors */
    gchar* temporaryFilename = NULL;
    GError* error = NULL;
    gint openedFile = g_file_open_tmp((const gchar*) template, &temporaryFilename, &error);
    if(openedFile < 0) {
        error("unable to open temporary file for preload library '%s': %s", originalPath, error->message);
    }

    /* now we ceanup and return the new filename */
    close(openedFile);
    g_free(template);

    GString* templatePath = g_string_new(temporaryFilename);
    g_free(temporaryFilename);
    return templatePath;
}

static gboolean _preload_copyFile(gchar* fromPath, gchar* toPath) {
    gchar* contents = NULL;
    gsize length = 0;
    GError* error = NULL;

    /* get the original file */
    if(!g_file_get_contents(fromPath, &contents, &length, &error)) {
        error("unable to read '%s' for copying: %s", fromPath, error->message);
        return FALSE;
    }
    error = NULL;

    /* copy to the new file */
    if(!g_file_set_contents(toPath, contents, (gssize)length, &error)) {
        error("unable to write private copy of '%s' to '%s': %s",
                fromPath, toPath, error->message);
        return FALSE;
    }

    /* ok, our private copy was created, cleanup */
    g_free(contents);
    return TRUE;
}

Preload* preload_new(const gchar* name, const gchar* path) {
    utility_assert(path);

    Preload* lib = g_new0(Preload, 1);
    MAGIC_INIT(lib);

    lib->id = g_quark_from_string((const gchar*) name);;
    lib->name = g_string_new(name);
    lib->path = g_string_new(path);

    /*
     * now get the plugin handle from the library at filename.
     *
     * @warning only global dlopens are searchable with dlsym
     * we cant use G_MODULE_BIND_LOCAL if we want to be able to lookup
     * functions using dlsym in the plugin itself. if G_MODULE_BIND_LOCAL
     * functionality is desired, then we must require plugins to separate their
     * intercepted functions to a SHARED library, and link the plugin to that.
     *
     * @note this will call g_module_check_init() in the preload library if it contains
     * that function.
     */
    /*lib->handle = g_module_open(lib->path->str, G_MODULE_BIND_LAZY|G_MODULE_BIND_LOCAL);*/
    lib->handle = g_module_open(lib->path->str, G_MODULE_BIND_LAZY);
    if(lib->handle) {
        message("successfully loaded private preload library '%s' at %p", lib->path->str, lib);
    } else {
        const gchar* errorMessage = g_module_error();
        critical("g_module_open() failed: %s", errorMessage);
        error("unable to load private preload library '%s'", lib->path->str);
    }

    /* make sure it has the required init function */
    gpointer initFunc = NULL;
    gpointer hoistedGlobals = NULL;
    gpointer hoistedGlobalsSize = NULL;
    gpointer hoistedGlobalsPointer = NULL;
    gboolean success = FALSE;

    success = g_module_symbol(lib->handle, PRELOADINITSYMBOL, &initFunc);
    if(success) {
        lib->init = initFunc;
        message("found '%s' at %p", PRELOADINITSYMBOL, initFunc);
    } else {
        const gchar* errorMessage = g_module_error();
        critical("g_module_symbol() failed: %s", errorMessage);
        error("unable to find the required function symbol '%s' in preload library '%s'",
                PRELOADINITSYMBOL, path);
    }

    success = g_module_symbol(lib->handle, PRELOADGLOBALSSYMBOL, &hoistedGlobals);
    if(success) {
        lib->residentState = hoistedGlobals;
        message("found '%s' at %p", PRELOADGLOBALSSYMBOL, hoistedGlobals);
    } else {
        const gchar* errorMessage = g_module_error();
        critical("g_module_symbol() failed: %s", errorMessage);
        error("unable to find the required merged globals struct symbol '%s' in preload library '%s'",
                PRELOADGLOBALSSYMBOL, path);
    }

    success = g_module_symbol(lib->handle, PRELOADGLOBALSPOINTERSYMBOL, &hoistedGlobalsPointer);
    if(success) {
        lib->residentStatePointer = hoistedGlobalsPointer;
        message("found '%s' at %p", PRELOADGLOBALSPOINTERSYMBOL, hoistedGlobalsPointer);
    } else {
        const gchar* errorMessage = g_module_error();
        critical("g_module_symbol() failed: %s", errorMessage);
        error("unable to find the required merged globals struct symbol '%s' in preload library '%s'",
                PRELOADGLOBALSPOINTERSYMBOL, path);
    }

    success = g_module_symbol(lib->handle, PRELOADGLOBALSSIZESYMBOL, &hoistedGlobalsSize);
    if(success) {
        utility_assert(hoistedGlobalsSize);
        gint s = *((gint*) hoistedGlobalsSize);
        lib->residentStateSize = (gsize) s;
        message("found '%s' of value '%i' at %p", PRELOADGLOBALSSIZESYMBOL, s, hoistedGlobalsSize);
    } else {
        const gchar* errorMessage = g_module_error();
        critical("g_module_symbol() failed: %s", errorMessage);
        error("unable to find the required merged globals struct symbol '%s' in preload library '%s'",
                PRELOADGLOBALSSIZESYMBOL, path);
    }

    return lib;
}

void preload_free(Preload* lib) {
    MAGIC_ASSERT(lib);

    if(lib->handle) {
        gboolean success = g_module_close(lib->handle);
        if(!success) {
            const gchar* errorMessage = g_module_error();
            warning("g_module_close() failed: %s", errorMessage);
            warning("failed closing plugin '%s'", lib->path->str);
        }
    }

    /* TODO: this unlink should be removed when we no longer copy plugins
     * before loading them. see the other TODO above in this file.
     */
    if(lib->isTemporary) {
        g_unlink(lib->path->str);
    }
    if(lib->path) {
        g_string_free(lib->path, TRUE);
    }
    if(lib->name) {
        g_string_free(lib->name, TRUE);
    }

    if(lib->defaultState) {
        preload_freeState(lib, lib->defaultState);
    }

    MAGIC_CLEAR(lib);
    g_free(lib);
}

Preload* preload_getTemporaryCopy(Preload* lib) {
    utility_assert(lib);

    /* do not open the path directly, but rather copy to tmp directory first
     * to avoid multiple threads using the same memory space.
     * TODO: this should eventually be replaced when we have thread-local
     * storage working correctly in the LLVM module-pass code */
    GString* pathCopy = _preload_getTemporaryFilePath(lib->path->str);

    /* now we need to copy the actual contents to our new file */
    if(!_preload_copyFile(lib->path->str, pathCopy->str)) {
        g_string_free(pathCopy, TRUE);
        return NULL;
    }

    Preload* libCopy = preload_new(lib->name->str, pathCopy->str);
    libCopy->isTemporary = TRUE;

    g_string_free(pathCopy, TRUE);

    return libCopy;
}

void preload_registerResidentState(Preload* lib) {
    MAGIC_ASSERT(lib);
    if(lib->isRegisterred) {
        warning("ignoring duplicate state registration");
        return;
    }

    /* also store a copy of the defaults as they exist now */
    info("copying resident plugin memory contents at %p-%p (%"G_GSIZE_FORMAT" bytes) as default start state",
            lib->residentState, lib->residentState+lib->residentStateSize, lib->residentStateSize);
    lib->defaultState = g_slice_copy(lib->residentStateSize, lib->residentState);
    info("stored default state at %p", lib->defaultState);

    /* dont change our resident state or defaults */
    lib->isRegisterred = TRUE;
}

void preload_swapInState(Preload* lib, PreloadState state) {
    MAGIC_ASSERT(lib);
    utility_assert(!lib->isExecuting);

    /* context switch from shadow to preload library library
     *
     * TODO: we can be smarter here - save a pointer to the last plugin that
     * was loaded... if the physical memory locations still has our state,
     * there is no need to copy it in again. similarly for stopExecuting()
     */
    /* destination, source, size */
    g_memmove(lib->residentState, state, lib->residentStateSize);

    lib->isExecuting = TRUE;
}

void preload_swapOutState(Preload* lib, PreloadState state) {
    MAGIC_ASSERT(lib);
    utility_assert(lib->isExecuting);

    lib->isExecuting = FALSE;

    /* destination, source, size */
    g_memmove(state, lib->residentState, lib->residentStateSize);
}

PreloadInitFunc preload_getInitFunc(Preload* lib) {
    MAGIC_ASSERT(lib);
    return lib->init;
}

PreloadState preload_newDefaultState(Preload* lib) {
    MAGIC_ASSERT(lib);
    return g_slice_copy(lib->residentStateSize, lib->defaultState);
}

void preload_freeState(Preload* lib, gpointer state) {
    MAGIC_ASSERT(lib);
    g_slice_free1(lib->residentStateSize, state);
}

GQuark* preload_getID(Preload* lib) {
    MAGIC_ASSERT(lib);
    return &(lib->id);
}

gboolean preload_isRegistered(Preload* lib) {
    MAGIC_ASSERT(lib);
    return lib->isRegisterred;
}

const gchar* preload_getName(Preload* lib) {
    MAGIC_ASSERT(lib);
    return lib->name->str;
}

gpointer preload_getFunction(Preload *lib, gchar* functionName) {
    MAGIC_ASSERT(lib);
    gpointer func;
    g_module_symbol(lib->handle, functionName, &func);
    return func;
}

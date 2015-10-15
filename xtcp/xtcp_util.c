#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include "xtcp_util.h"

#define HT_SIZE 1024

struct queue_s {
    void *data;
    queue_t *next;
    int qlen;
};

struct buffer_s {
    unsigned char *data;
    size_t len;
    size_t size;
};


typedef struct hashtable_entry_s hashtable_entry_t;
struct hashtable_entry_s {
    int key;
    void* value;
    hashtable_entry_t *prev, *next;
    hashtable_entry_t *global_prev, *global_next;
};

struct hashtable_s {
    hashtable_entry_t *entries[HT_SIZE];
    hashtable_entry_t *head, *tail;
    int size;
};

// TODO no global variables!!!
FILE *logfp = NULL;
XTCPLogLevel min_log_level = XTCP_LOG_UNKNOWN;

XTCPLogLevel xtcp_log_level() {
    return min_log_level;
}

void xtcp_log(XTCPLogLevel log_level, const char *filename, const char *function_name, int lineno, const char *format, ...) {
    time_t now;
    struct tm *tm_info;
    char time_buffer[32];

    if(!logfp) {
        char *logfilename = getenv("XTCP_LOG");
        if(!logfilename) {
            logfp = stderr;
        } else {
            logfp = fopen(logfilename, "w");
        }
    }

    if(min_log_level == XTCP_LOG_UNKNOWN) {
        XTCPLogLevel min_log_level = XTCP_LOG_MESSAGE;
        char *loglevel = getenv("XTCP_LOG_LEVEL");
        if(loglevel) {
            if(!strcasecmp(loglevel, "debug")) {
                min_log_level = XTCP_LOG_DEBUG;
            } else if(!strcasecmp(loglevel, "info")) {
                min_log_level = XTCP_LOG_INFO;
            } else if(!strcasecmp(loglevel, "message")) {
                min_log_level = XTCP_LOG_MESSAGE;
            } else if(!strcasecmp(loglevel, "warning")) {
                min_log_level = XTCP_LOG_WARNING;
            } else if(!strcasecmp(loglevel, "error")) {
                min_log_level = XTCP_LOG_ERROR;
            }
        }
    }

    if(log_level <= min_log_level) {
        return;
    }


    char hostname[128];
    gethostname(hostname, 128);

    time(&now);
    tm_info = localtime(&now);
    strftime(time_buffer, 32, "%Y-%m-%d %H:%M:%S", tm_info);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms = round(ts.tv_nsec / 1.0e6);

    fprintf(logfp, "[%s] [%s.%03ld] ", hostname, time_buffer, ms);

    switch(log_level) {
        case XTCP_LOG_DEBUG:
            fprintf(logfp, "[DEBUG] ");
            break;
        case XTCP_LOG_INFO:
            fprintf(logfp, "[INFO] ");
            break;
        case XTCP_LOG_MESSAGE:
            fprintf(logfp, "[MESSAGE] ");
            break;
        case XTCP_LOG_WARNING:
            fprintf(logfp, "[WARNING] ");
            break;
        case XTCP_LOG_ERROR:
            fprintf(logfp, "[ERROR] ");
            break;
        default:
            fprintf(logfp, "[?????] ");
            break;
    }

    fprintf(logfp, "[%s@%s:%d] ", function_name, filename, lineno);

    va_list vargs;
    va_start(vargs, format);
    vfprintf(logfp, format, vargs);
    va_end(vargs);

    fprintf(logfp, "\n");
}

/*
 * queue functions
 */

void queue_push(queue_t **head, void *data) {
    queue_t *item = (queue_t *)malloc(sizeof(*item));
    memset(item, 0, sizeof(*item));

    item->data = data;
    item->next = NULL;

    queue_t *iter = *head;

    if(!iter) {
        *head = item;
    } else {
        while(iter->next) {
            iter = iter->next;
        }
        iter->next = item;
    }
    
    (*head)->qlen++;
}

void *queue_pop(queue_t **head) {
    queue_t *oldhead = *head;
    if(!oldhead) {
        return NULL;
    }

    void *data = (*head)->data;
    *head = oldhead->next;
    if(*head) {
       (*head)->qlen = oldhead->qlen - 1;
    }
    free(oldhead);

    return data;
}

int queue_length(queue_t *head) {
    if(!head) {
        return 0;
    }
    return head->qlen;
}

void queue_free(queue_t *head) {
    queue_t *iter = head;
    while(iter) {
        queue_t *curr = iter;
        iter = iter->next;
        free(curr);
    }
}


/*
 * Buffer functions
 */

buffer_t *buffer_new() {
    buffer_t *buffer = (buffer_t *)malloc(sizeof(*buffer));
    memset(buffer, 0, sizeof(*buffer));
    return buffer;
}

void buffer_append(buffer_t *buffer, unsigned char *data, size_t datalen) {
    size_t newsize = buffer->size;
    while(buffer->len + datalen > newsize) {
        newsize = MAX(newsize, 1) * 2;
    }

    if(buffer->size < newsize) {
        buffer->data = (unsigned char *)realloc(buffer->data, newsize);
        buffer->size = newsize;
    }

    memcpy(buffer->data + buffer->len, data, datalen);
    buffer->len += datalen;
}

size_t buffer_length(buffer_t *buffer) {
    return buffer->len;
}

void buffer_copy_bytes(buffer_t *buffer, unsigned char *data, size_t bytes) {
    memcpy(data, buffer->data, bytes);
}

void buffer_pop_bytes(buffer_t *buffer, unsigned char *data, size_t bytes) {
    buffer_copy_bytes(buffer, data, bytes);
    memmove(buffer->data, buffer->data + bytes, buffer->len - bytes);
    buffer->len -= bytes;

    if(buffer->len * 2 < buffer->size) {
        buffer->size /= 2;
        buffer->data = (unsigned char *)realloc(buffer->data, buffer->size);
    }
}

void buffer_free(buffer_t *buffer) {
    free(buffer->data);
    free(buffer);
}


/*
 * Hash table functions
 */

unsigned int _hashint(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x);
    return x;
}

hashtable_entry_t *_hashtable_find_entry(hashtable_t *table, int key) {
    int idx = _hashint(key) % HT_SIZE;

    hashtable_entry_t *entry = table->entries[idx];
    while(entry) {
        if(entry->key == key) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

hashtable_t *hashtable_create() {
    hashtable_t *ht = (hashtable_t *)malloc(sizeof(*ht));
    memset(ht, 0, sizeof(*ht));
    return ht;
}

void *hashtable_lookup(hashtable_t *table, int key) {
    hashtable_entry_t *entry = _hashtable_find_entry(table, key);
    if(!entry) {
        return NULL;
    }

    return entry->value;
}

void *hashtable_insert(hashtable_t *table, int key, void *value) {
    hashtable_entry_t *entry = _hashtable_find_entry(table, key);
    if(entry) {
        void *oldvalue = entry->value;
        entry->value = value;
        return oldvalue;
    }

    entry = (hashtable_entry_t *)malloc(sizeof(*entry));
    memset(entry, 0, sizeof(*entry));
    entry->key = key;
    entry->value = value;

    /* finx the bucket to add the entry to */
    int idx = _hashint(key) % HT_SIZE;
    entry->next = table->entries[idx];
    if(entry->next) {
        entry->next->prev = entry;
    }
    table->entries[idx] = entry;

    /* add it to the global list of entries */
    if(!table->head) {
        table->head = table->tail = entry;
    } else {
        table->tail->global_next = entry;
        entry->global_prev = table->tail;
        table->tail = entry;
    }

    table->size++;

    return NULL;
}    

void *hashtable_remove(hashtable_t *table, int key) {
    hashtable_entry_t *entry = _hashtable_find_entry(table, key);
    if(!entry) {
        return NULL;
    }

    if(entry->prev) {
        entry->prev->next = entry->next;
    }
    if(entry->next) {
        entry->next->prev = entry->prev;
    }
    if(!entry->prev && !entry->next) {
        int idx = _hashint(key) % HT_SIZE;
        table->entries[idx] = NULL;
    }

    if(table->head == entry) {
        table->head = entry->global_next;
    }
    if(table->tail == entry) {
        table->tail = entry->global_prev;
    }
    if(entry->global_prev) {
        entry->global_prev->global_next = entry->global_next;
    }
    if(entry->global_next) {
        entry->global_next->global_prev = entry->global_prev;
    }

    void *value = entry->value;
    free(entry);

    table->size--;

    return value;
}

int *hashtable_getkeys(hashtable_t *table) {
    assert(table);

    int *keys = (void *)malloc(sizeof(int) * (table->size + 1));
    memset(keys, 0, sizeof(void*) * (table->size + 1));

    int idx = 0;
    hashtable_entry_t *iter = table->head;
    while(iter) {
        keys[idx] = iter->key;
        idx++;
        iter = iter->next;
    }
    
    return keys;
}

void **hashtable_getvalues(hashtable_t *table) {
    assert(table);

    void **values = (void *)malloc(sizeof(void*) * (table->size + 1));
    memset(values, 0, sizeof(void*) * (table->size + 1));

    int idx = 0;
    hashtable_entry_t *iter = table->head;
    while(iter) {
        values[idx] = iter->value;
        idx++;
        iter = iter->next;
    }
    
    return values;
}

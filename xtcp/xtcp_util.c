#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "xtcp_util.h"

#define HT_SIZE 1024

struct queue_s {
    void *data;
    queue_t *next;
    int qlen;
};

struct buffer_s {
    unsigned char *data;
    int len;
    int size;
};


typedef struct hashtable_entry_s hashtable_entry_t;
struct hashtable_entry_s {
    int key;
    void* value;
    hashtable_entry_t *prev, *next;
};

struct hashtable_s {
    hashtable_entry_t *entries[HT_SIZE];
    int size;
};

FILE *logfp = NULL;

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

    time(&now);
    tm_info = localtime(&now);
    strftime(time_buffer, 32, "%Y-%m-%d %H:%M:%S", tm_info);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms = round(ts.tv_nsec / 1.0e6);

    fprintf(logfp, "[%s.%03ld] ", time_buffer, ms);

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

void buffer_append(buffer_t *buffer, unsigned char *data, int datalen) {
    int newsize = buffer->size;
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

int buffer_length(buffer_t *buffer) {
    return buffer->len;
}

void buffer_copy_bytes(buffer_t *buffer, unsigned char *data, int bytes) {
    memcpy(data, buffer->data, bytes);
}

void buffer_pop_bytes(buffer_t *buffer, unsigned char *data, int bytes) {
    buffer_copy_bytes(buffer, data, bytes);
    memcpy(buffer->data, buffer->data + bytes, buffer->len - bytes);
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

    int idx = _hashint(key) % HT_SIZE;
    entry->next = table->entries[idx];
    if(entry->next) {
        entry->next->prev = entry;
    }
    table->entries[idx] = entry;

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

    void *value = entry->value;
    free(entry);

    return value;
}



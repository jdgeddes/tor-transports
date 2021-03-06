#ifndef XTCP_UTIL_H
#define XTCP_UTIL_H

#define xtcp_debug(...) xtcp_log(XTCP_LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define xtcp_info(...) xtcp_log(XTCP_LOG_INFO, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define xtcp_message(...) xtcp_log(XTCP_LOG_MESSAGE, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define xtcp_warning(...) xtcp_log(XTCP_LOG_WARNING, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define xtcp_error(...) xtcp_log(XTCP_LOG_ERROR, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

typedef struct queue_s queue_t;
typedef struct buffer_s buffer_t;
typedef struct hashtable_s hashtable_t;

typedef enum XTCPLogLevel {
    XTCP_LOG_UNKNOWN = 0,
    XTCP_LOG_DEBUG = 1,
    XTCP_LOG_INFO = 2,
    XTCP_LOG_MESSAGE = 3,
    XTCP_LOG_WARNING = 4,
    XTCP_LOG_ERROR = 5,
} XTCPLogLevel;

XTCPLogLevel xtcp_log_level();
void xtcp_log(XTCPLogLevel log_level, const char *filename, const char *function_name, int lineno, const char *format, ...);

void queue_push(queue_t **head, void *data);
void *queue_pop(queue_t **head);
int queue_length(queue_t *head);

buffer_t *buffer_new();
void buffer_append(buffer_t *buffer, unsigned char *data, size_t datalen);
size_t buffer_length(buffer_t *buffer);
void buffer_copy_bytes(buffer_t *buffer, unsigned char *data, size_t bytes);
void buffer_pop_bytes(buffer_t *buffer, unsigned char *data, size_t bytes);
void buffer_free(buffer_t *buffer);

hashtable_t *hashtable_create();
void *hashtable_lookup(hashtable_t *table, int key);
void *hashtable_insert(hashtable_t *table, int key, void *value);
void *hashtable_remove(hashtable_t *table, int key);
int *hashtable_getkeys(hashtable_t *table);
void **hashtable_getvalues(hashtable_t *table);


#endif

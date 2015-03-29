#ifndef MAIN_H
#define MAIN_H

#define MAX_NAME_LENGTH 64
#define TOX_ID_SIZE 38 //note: assumed to be smaller than MAX_NAME_LENGTH

#define TOXDNS3_RESPONSE_SIZE 90

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <unistd.h>

#include <pthread.h>

pthread_mutex_t database_mutex;

struct
{
    uint8_t public[32];
    uint8_t private[32];
}key;

struct
{
    uint64_t registered, requests;
}stat;

#include "http.h"
#include "database.h"
#include "crypto.h"
#include "util.h"

#ifndef INDEX_NAME
#define INDEX_NAME "index.htm"
#endif

#ifndef NO_DEBUG
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...)
#endif

#ifndef NO_PRINT
#define print(...) printf(__VA_ARGS__)
#else
#define print(...)
#endif

#ifdef DEBUG_HARD
#define debug_hard(...) printf(__VA_ARGS__)
#else
#define debug_hard(...)
#endif

#endif // MAIN_H

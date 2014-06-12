#ifndef MAIN_H
#define MAIN_H

#define MAX_NAME_LENGTH 64
#define TOX_ID_SIZE 38

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

#include "http.h"
#include "database.h"
#include "util.h"

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

#endif // MAIN_H

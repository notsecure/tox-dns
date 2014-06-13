#include "main.h"

#define NO_FCGI_DEFINES
#include <fcgi_stdio.h>

#include <arpa/inet.h>

static uint8_t *index_data, *index_end;
static uint32_t index_size, index_end_size;

static _Bool init(void) {
    FILE *file;
    size_t r;

    file = fopen("index.htm", "rb");
    if(!file) {
        return 0;
    }

    fseek(file, 0, SEEK_END);
    index_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    index_data = malloc(index_size);
    r = fread(index_data, index_size, 1, file);
    fclose(file);

    if(r != 1) {
        free(index_data);
        return 0;
    }

    uint8_t *p = index_data;
    while(*p++ != '*'){}

    r = p - index_data;
    index_end_size = index_size - r;
    index_size = r - 1;
    index_end = p;

    return 1;
}

enum
{
    ERROR_INTERNAL = -7,
    INVALID_CHARS_NAME = -6,
    INVALID_LENGTH = -5,
    INVALID_CHARS = -4,
    INVALID_CHECKSUM = -3,
    REJECTED_SPAM = -2,
    REJECTED_NAME = -1,
    SUCCESS = 0,
};

static const char *result[] = {
    "",
    "Success",
    "Name already taken",
    "Failure (anti-spam)",
    "Invalid Tox ID (invalid checksum)",
    "Invalid Tox ID (invalid characters)",
    "Invalid Tox ID (length)",
    "Invalid Name (valid: a-z, 0-9)",
    "Internal Error",
};

static int8_t do_query(char *query, char *address)
{
    uint32_t ip;
    if(!inet_pton(AF_INET, address, &ip)) {
        return ERROR_INTERNAL;
    }

    char *name = strstr(query, "name="), *id = strstr(query, "id="), *c;
    uint32_t len;
    uint8_t name_length;
    if(name && id) {
        name += 5;
        id += 3;
        c = name;
        while(*c != '&'&& *c) {
            if(*c >= 'A' && *c <= 'Z') {
                *c = *c - 'A' + 'a'; c++;
                continue;
            }
            if(!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9'))) {
                return INVALID_CHARS_NAME;
            }
            c++;
        }
        len = c - name;
        if(len >= MAX_NAME_LENGTH) {
            len = MAX_NAME_LENGTH;
        }
        name_length = len;
        c = id;
        while(*c != '&'&& *c){c++;}
        len = c - id;
        if(len != TOX_ID_SIZE * 2) {
            return INVALID_LENGTH;
        }

        uint8_t _id[TOX_ID_SIZE];
        if(!string_to_id(_id, (uint8_t*)id)) {
            return INVALID_CHARS;
        }

        if(!validate_id(_id)) {
            return INVALID_CHECKSUM;
        }

        return database_write(_id, (uint8_t*)name, name_length, ip);

    } else {
        return 1;
    }
}

void http_thread(void *args)
{
    if(!init()) {
        print("http_init() failed\n");
        return;
    }

    while(FCGI_Accept() >= 0)
    {
        FCGI_printf("Content-type: text/html\r\nStatus: 200 OK\r\n\r\n");


        int8_t res = do_query(getenv("QUERY_STRING"), getenv("REMOTE_ADDR"));

        if(strcmp(getenv("SCRIPT_NAME"), "/q") == 0) {
            FCGI_printf("%i", res);
            continue;
        }

        FCGI_fwrite(index_data, index_size, 1, FCGI_stdout);

        FCGI_printf("%s", result[-res + 1]);

        FCGI_fwrite(index_end, index_end_size, 1, FCGI_stdout);


        /*char *script_name = getenv("SCRIPT_NAME"), *query_string = getenv("QUERY_STRING");

        printf("SCRIPT_NAME: %s<br/>QUERY_STRING: %s<br/>", script_name, query_string);*/


    }
}

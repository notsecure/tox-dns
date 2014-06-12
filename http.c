#include "main.h"

#define NO_FCGI_DEFINES
#include <fcgi_stdio.h>

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

static void do_query(char *query)
{
    if(!query) {
        //is this even possible?
        return;
    }

    char *name = strstr(query, "name="), *id = strstr(query, "id="), *c;
    uint32_t len;
    uint8_t name_length;
    if(name && id) {
        name += 5;
        id += 3;
        c = name;
        while(*c != '&'&& *c++){}
        len = c - name;
        if(len >= MAX_NAME_LENGTH) {
            len = MAX_NAME_LENGTH;
        }
        name_length = len;
        c = id;
        while(*c != '&'&& *c){c++;}
        len = c - id;
        if(len != TOX_ID_SIZE * 2) {
            FCGI_printf("Invalid Tox ID (length %u)\n", len);
            return;
        }

        uint8_t _id[TOX_ID_SIZE];
        if(!string_to_id(_id, (uint8_t*)id)) {
            FCGI_printf("Invalid Tox ID (invalid characters)");
            return;
        }

        if(!validate_id(_id)) {
            FCGI_printf("Invalid Tox ID (invalid checksum)");
            return;
        }

        int8_t r = database_write(_id, (uint8_t*)name, name_length, 0);
        if(r == -2) {
            FCGI_printf("Failure (anti-spam)");
            return;
        }

        if(r == -1) {
            FCGI_printf("Name already taken");
            return;
        }

        FCGI_printf("Success");

    } else {
        return;
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

        FCGI_fwrite(index_data, index_size, 1, FCGI_stdout);

        do_query(getenv("QUERY_STRING"));

        FCGI_fwrite(index_end, index_end_size, 1, FCGI_stdout);


        /*char *script_name = getenv("SCRIPT_NAME"), *query_string = getenv("QUERY_STRING");

        printf("SCRIPT_NAME: %s<br/>QUERY_STRING: %s<br/>", script_name, query_string);*/


    }
}

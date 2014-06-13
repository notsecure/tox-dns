#include "main.h"

#define INT32(p) ((p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24))

typedef struct
{
    uint16_t ip;
    uint8_t n;
    _Bool next;
}IP_ENTRY;

/* name_entry format
    4 bytes 32bit int (le) address in data of next entry
    1 byte namelen
    namelen bytes name
    TOX_ID_SIZE bytes tox id
 */

static _Bool update_table;
static uint32_t table[65536];
static IP_ENTRY *iptable[65536];

static uint8_t data[65536 * 256], *datap, *dataq;


static uint16_t hashfunc(uint8_t *str, uint8_t length)
{
    /* change this to something real, and involving a secret number */
    uint16_t res = 0;
    uint8_t i;
    for(i = 0; i < 4 && i < length; i++) {
        res |= (str[i] & 15) << (i * 4);
    }

    return res;
}

static void* writeentry(uint8_t *p, uint8_t *publickey, uint8_t *name, uint8_t name_length)
{
    memset(p, 0xFF, 4); p += 4;
    *p++ = name_length;
    memcpy(p, name, name_length); p += name_length;
    memcpy(p, publickey, TOX_ID_SIZE); p += TOX_ID_SIZE;

    return p;
}

static _Bool allowip(uint32_t ip)
{
    uint16_t low = ip & 0xFFFF, high = ip >> 16;
    if(iptable[low]) {
        IP_ENTRY *root = iptable[low], *i = root;
        while(i->next) {
            if(i->ip == high) {
                if(i->n == 15) {
                    return 0;
                } else {
                    i->n++;
                    return 1;
                }
            }
            i++;
        }

        uint16_t index = i - root + 1;
        root = realloc(root, (index + 1) * sizeof(IP_ENTRY));
        if(!root) {
            //out of memory
            return 0;
        }

        i = root + index;
        iptable[low] = root;

        (i - 1)->next = 1;
        i->ip = high;
        i->n = 0;
        i->next = 0;
    } else {
        IP_ENTRY *i = iptable[low] = malloc(sizeof(IP_ENTRY));
        i->ip = high;
        i->n = 0;
        i->next = 0;
    }

    return 1;
}

static int8_t _write(uint8_t *id, uint8_t *name, uint8_t name_length, uint32_t src_ip)
{
    uint16_t hash = hashfunc(name, name_length);
    if(table[hash] != ~0) {
        uint32_t offset;
        uint8_t *p = data + table[hash];
        do
        {
            if(p[4] == name_length && memcmp(p + 5, name, name_length) == 0) {
                return -1;
            }
        } while((offset = INT32(p)) != ~0 && ((p = data + offset) || 1));

        offset = datap - data;
        *p++ = offset; *p++ = offset >> 8;
        *p++ = offset >> 16; *p++ = offset >> 24;
    } else {
        table[hash] = datap - data;
        update_table = 1;
    }

    datap = writeentry(datap, id, name, name_length);
    return 0;
}

int8_t database_write(uint8_t *id, uint8_t *name, uint8_t name_length, uint32_t src_ip)
{
    pthread_mutex_lock(&database_mutex);
    int8_t res;
    if(!allowip(src_ip)) {
        res = -2;
    } else {
        res = _write(id, name, name_length, src_ip);
    }
    pthread_mutex_unlock(&database_mutex);
    return res;
}

static uint8_t* _find(uint8_t *name, uint8_t name_length)
{
    uint16_t hash = hashfunc(name, name_length);
    if(table[hash] != ~0) {
        uint32_t offset;
        uint8_t *p = data + table[hash];
        do
        {
            if(p[4] == name_length && memcmp(p + 5, name, name_length) == 0) {
                return p + 5 + name_length;
            }
        } while((offset = INT32(p)) != ~0 && ((p = data + offset) || 1));
    }

    return NULL;
}

uint8_t* database_find(uint8_t *name, uint8_t name_length)
{
    /*note: assumes that the data pointed by res wont be modified afterwards:
     ->change this when needed by having it copied to a buffer instead*/
    pthread_mutex_lock(&database_mutex);
    uint8_t *res = _find(name, name_length);
    pthread_mutex_unlock(&database_mutex);
    return res;
}

static _Bool init(void)
{
    FILE *file;
    size_t r;

    file = fopen("table", "rb");
    if(file) {
        r = fread(table, sizeof(table), 1, file);
    } else {
        file = fopen("table", "wb");
        if(!file) {
            return 0;
        }

        memset(table, 0xFF, sizeof(table));
        r = fwrite(table, sizeof(table), 1, file);
    }

    fclose(file);
    if(r != 1) {
        return 0;
    }

    file = fopen("data", "rb");
    if(file) {
        fseek(file, 0, SEEK_END);
        r = ftell(file);
        fseek(file, 0, SEEK_SET);
        dataq = datap = data + r;

        r  = fread(data, r, 1, file);
        fclose(file);
        if(r != 1) {
            return 0;
        }
    } else {
        dataq = datap = data;
    }

    return 1;
}

void database_thread(void *args)
{
    if(!init()) {
        print("database_init() failed\n");
        return;
    }

    FILE *file;
    size_t r;
    uint16_t sec = 0;

    while(1) {
        pthread_mutex_lock(&database_mutex);

        /* append new data */
        if(dataq != datap) {
            file = fopen("data", "ab");
            if(file) {
                //!TODO: verify that file has correct size
                r = fwrite(dataq, datap - dataq, 1, file);
                fclose(file);

                if(r != 1) {
                    print("update error, database will be corrupted\n");
                }
            } else {
                print("update error, database will be corrupted\n");
            }

            dataq = datap;
        }

        /* update table */
        //!TODO: something better than just rewriting the whole table
        if(update_table) {
            update_table = 0;

            file = fopen("table", "wb");
            if(file) {
                r = fwrite(table, sizeof(table), 1, file);
                fclose(file);
                if(r != 1) {
                    print("update error, database will be corrupted\n");
                }
            } else {
                print("update error, database will be corrupted\n");
            }
        }

        /* clear the ip table every ~10 minutes */
        if(sec == 60 * 10) {
            int i;
            for(i = 0; i != 0x10000; i++) {
                if(iptable[i]) {
                    free(iptable[i]);
                    iptable[i] = NULL;
                }
            }
            sec = 0;
        }

        pthread_mutex_unlock(&database_mutex);
        sleep(1);
        sec++;
    }
}


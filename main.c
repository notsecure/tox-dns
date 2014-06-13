#include "main.h"

#if BYTE_ORDER == BIG_ENDIAN
#define HTONS(x) (x)
#else
#define HTONS(x) (uint16_t)(((x) >> 8) | ((x) << 8))
#endif

typedef struct {
    uint16_t id;
    uint8_t flags[2];
    uint16_t qdcount, ancount, nscount, arcount;
} HEADER;

int sock;
struct {
    uint16_t family, port;
    uint8_t ip[4], pad[8];
}addr = {
    .family = AF_INET,
    .port = (53) << 8,
};

uint8_t ip[4] = {162, 253, 64, 31};

static void thread(void func(void*), void *args)
{
    pthread_t thread_temp;
    pthread_create(&thread_temp, NULL, (void*(*)(void*))func, args);
}

static _Bool net_init(void)
{
    if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        debug("socket() failed\n");
        return 0;
    }

    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        debug("bind() failed\n");
        return 0;
    }

    return 1;
}

int main(void)
{
    if(!crypto_init()) {
        return 1;
    }

    if(pthread_mutex_init(&database_mutex, NULL) != 0) {
        debug("pthread_mutex_init failed\n");
        return 1;
    }

    thread(http_thread, NULL);
    thread(database_thread, NULL);

    if(!net_init()) {
        return 1;
    }

    int len;
    uint32_t addrlen;
    uint8_t data[65536];
    while((addrlen = sizeof(addr)) && (len = recvfrom(sock, data, sizeof(data), 0, (struct sockaddr*)&addr, &addrlen)) >= 0) {
        if(len < sizeof(HEADER)) {
            debug("small packet\n");
            continue;
        }

        HEADER *h = (void*)data;
        uint8_t *p = data + sizeof(HEADER), *op, *end = data + len, *name, atype = 0;

        debug("request from: %u.%u.%u.%u:%u (%u, %u)\n", addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3], HTONS(addr.port), len, HTONS(h->id));

        if(h->flags[0] & (0x80 | 0x78)) {
            //only care about requests and QUERY
            debug("response or not QUERY (%u)\n", h->flags[0]);
            continue;
        }

        if(h->ancount) {
            //dont support answer entries
            debug("has answer entries\n");
            continue;
        }

        if(h->nscount) {
            //dont support authority entries
            debug("has authority entries\n");
            continue;
        }

        //qr (1), opcode (4), aa (1), tc (1), rd (1)
        //ra (1), unused (1), ad (1), cd (1), rcode (4)
        h->flags[0] = ((1 << 7) | (0 << 3) | (0 << 2) | (0 << 1) | (h->flags[0] & 1));
        h->flags[1] = (0);

        uint32_t ttl;
        uint16_t i, n, type, class, size;
        uint8_t len;

        n = HTONS(h->qdcount);
        for(i = 0; i != n; i++) {
            if(p == end) {
                debug("malformed question\n");
                goto CONTINUE;
            }

            if(i == 0) {
                name = p;
            }

            while((len = *p++)) {
                if(p + len + 1 > end){
                    debug("malformed question\n");
                    goto CONTINUE;
                }
                p += len;
            }

            if(p + 4 > end) {
                debug("malformed question\n");
                goto CONTINUE;
            }

            type = (p[1] | (p[0] << 8)); p += 2;
            class = (p[1] | (p[0] << 8)); p += 2;
            debug_hard("QTYPE: %u QCLASS: %u\n", type, class);

            switch(type) {
                case 1: //A
                case 15: //MX
                case 16: //TXT
                case 28: //AAAA
                    break;

                default: {
                    debug("unknown QTYPE %u\n", type);
                    break;
                }
            }

            if(i != 0) {
                debug("more than one question\n");
                continue;
            }

            if(type == 0 || type >= 256) {
                debug("zero/large type\n");
                continue;
            }

            op = p;
            atype = type;
        }

        n = HTONS(h->arcount);
        for(i = 0; i != n; i++) {
            if(p == end) {
                debug("malformed resource\n");
                goto CONTINUE;
            }

            while((len = *p++)) {
                if(p + len + 1 > end){
                    debug("malformed resource\n");
                    goto CONTINUE;
                }
                p += len;
            }

            if(p + 10 > end) {
                debug("malformed resource\n");
                goto CONTINUE;
            }

            type = (p[1] | (p[0] << 8)); p += 2;
            class = (p[1] | (p[0] << 8)); p += 2;
            ttl = (p[3] | (p[2] << 8) | (p[1] << 16) | (p[0] << 24)); p += 4;
            size = (p[1] | (p[0] << 8)); p += 2;

            if(p + size > end) {
                debug("malformed resource\n");
                goto CONTINUE;
            }

            debug_hard("TYPE: %u CLASS: %u TTL: %u size: %u\n", type, class, ttl, size);

            switch(type) {
                case 41: {
                    /* OPT */
                    break;
                }

                default: {
                    debug("unknown RR TYPE %u\n", type);
                    break;
                }
            }

            p += size;
        }

        if(p == end && atype) {
            h->ancount = HTONS(1);
            h->qdcount = HTONS(1);
            h->arcount = 0;

            *op++ = 0xC0; *op++ = 12; //name at +12
            *op++ = 0; *op++ = atype; //type
            *op++ = 0; *op++ = 1; //class: IN

            memset(op, 0, 4); op += 4; //ttl: 0

            if(atype == 1) {
                /* A */
                *op++ = 0; *op++ = 4;
                memcpy(op, ip, 4); op += 4;
            }
            else if(atype == 16) {
                /* TXT */
                #define noresult() *op++ = 0; *op++ = 1; *op++ = 0; goto SEND;
                if(*name == 0) {
                    noresult();
                }

                debug("query for %.*s\n", *name, name + 1);
                if(name[1] == '_') {
                    /* crypto query */
                    //name[1] = name[0] - 1;
                    if(!crypto_readrequest(op + 13, name)) {
                        noresult();
                    }

                    #define SIZE (93 + 10)
                    *op++ = 0; *op++ = SIZE + 1;
                    *op++ = SIZE;
                    #undef SIZE

                    memcpy(op, "v=tox3;id=", 10); op += 10;
                    op += 93;

                    debug("id: %.*s\n", 93, op - 93);

                } else {
                    uint8_t *key;
                    if((key = database_find(name + 1, *name)) == NULL) {
                        noresult();
                    }

                    #define SIZE (TOX_ID_SIZE * 2 + 10)
                    *op++ = 0; *op++ = SIZE + 1;
                    *op++ = SIZE;
                    #undef SIZE

                    memcpy(op, "v=tox1;id=", 10); op += 10;
                    id_to_string(op, key); op += TOX_ID_SIZE * 2;

                    debug("id: %.*s\n", TOX_ID_SIZE * 2, op - TOX_ID_SIZE * 2);
                }
                #undef noresult
            } else {
                /* empty response for unhandled queries */
                *op++ = 0; *op++ = 0;
            }

            SEND:
            sendto(sock, data, op - data, 0, (struct sockaddr*)&addr, addrlen);
            debug_hard("sent response!\n");
        } else {
            debug("malformed packet\n");
        }

        CONTINUE:;
    }

    return 0;
}

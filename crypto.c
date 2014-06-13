#include "main.h"
#include <sodium.h>

#if crypto_box_PUBLICKEYBYTES != 32
#error "PUBLICKEYBYTES not 32"
#endif

#if crypto_box_SECRETKEYBYTES != 32
#error "SECRETKEYBYTES not 32"
#endif

#if crypto_box_BOXZEROBYTES != 16
#error "BOXZEROBYTES not 16"
#endif

#if crypto_box_ZEROBYTES != 32
#error "ZEROBYTES not 32"
#endif

#if crypto_box_NONCEBYTES != 24
#error "NONCEBYTES not 24"
#endif

static struct
{
    uint8_t public[32];
    uint8_t private[32];
}key;

_Bool crypto_init(void)
{
    FILE *file;
    size_t r;

    file = fopen("keys", "rb");
    if(file) {
        r = fread(&key, sizeof(key), 1, file);
        fclose(file);
        if(r != 1) {
            return 0;
        }
    } else {
        file = fopen("keys", "wb");
        if(!file) {
            return 0;
        }

        crypto_box_keypair(key.public, key.private);
        r = fwrite(&key, sizeof(key), 1, file);

        if(r != 1) {
            return 0;
        }
    }

    return 1;
}

static uint8_t decode(uint8_t *dest, uint8_t *src)
{
    uint8_t s[] = {4, 20, 32, 32, MAX_NAME_LENGTH, 0xFF}, *sp = s;

    uint8_t *p = src, *op = dest, *end, bits = 0, len, l = 0;
    *op = 0;
    while((len = *p++) && *p != '_') {
        end = p + len;
        while(p != end) {
            uint8_t ch = *p++;
            switch(ch) {
                case 'A' ... 'Z': {
                    ch = ch - 'A';
                    break;
                }

                case 'a' ... 'z': {
                    ch = ch - 'a';
                    break;
                }

                case '0' ... '5': {
                    ch = ch - '0' + 26;
                    break;
                }

                default: {
                    return 0;
                }
            }

            *op |= (ch << bits);
            bits += 5;
            if(bits > 8) {
                bits -= 8;
                l++;
                if(l == *sp) {
                    l = 0;
                    sp++;
                    if(*sp == 0xFF) {
                        return 0;
                    }
                    op += *sp++;
                } else {
                    op++;
                }


                *op = (ch >> (5 - bits));
            }
        }
    }

    if(sp - s != 4) {
        return 0;
    }

    return l + 1;
}

static const char base32[32] = {"abcdefghijklmnopqrstuvwxyz012345"};

#define _encode(a, b, c) \
{ \
    uint8_t i; \
    for(i = 0; i != c; i++ ) { \
        *a++ = base32[((b[0] >> bits) | (b[1] << (8 - bits))) & 0x1F]; \
        bits += 5; \
        if(bits >= 8) { \
            bits -= 8; \
            b++; \
        } \
    } \
} \

static void encode(uint8_t *dest, uint8_t *src)
{
    uint8_t bits = 0;
    _encode(dest, src, 4);
    src += 32 + 32;
    _encode(dest, src, TOX_ID_SIZE);
}

_Bool crypto_readrequest(uint8_t *out, uint8_t *text)
{
    /*nonce (24) + pubkey (32) + data (32 + name)*/
    uint8_t data[24 + 32 + 32 + MAX_NAME_LENGTH], dest[32 + MAX_NAME_LENGTH], sharedkey[32];
    #define src (data + 24 + 32)
    #define name (src + 32)
    int8_t len;

    len = decode(data, text);
    if(len == -1) {
        return 0;
    }

    crypto_box_beforenm(sharedkey, data + 24, key.private);

    memset(data + 24 + 32, 0, 32);
    memset(data + 4, 0, 20);

    if(crypto_box_open_afternm(dest, src, 32 + len, data, sharedkey) != 0) {
        return 0;
    }

    uint8_t *id = database_find(name, len);
    if(!id) {
        return 0;
    }

    memcpy(dest + 32, id, TOX_ID_SIZE);
    data[4] = 1;

    crypto_box_afternm(src, dest, 32 + TOX_ID_SIZE, data, sharedkey);

    name[TOX_ID_SIZE] = 0;
    encode(out, data);

    return 1;

    #undef src
    #undef name
}

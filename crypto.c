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
        fclose(file);

        if(r != 1) {
            return 0;
        }
    }

    return 1;
}

static int8_t decode(uint8_t *dest, uint8_t *src)
{
    _Bool underscore = 0;
    uint8_t s[] = {4, 20, 32, 16, MAX_NAME_LENGTH + 16, 0xFF}, *sp = s;

    uint8_t *p = src, *op = dest, *end, bits = 0, len, l = 0;
    *op = 0;
    while((len = *p++) && *p != underscore) {
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

                case '_': {
                    if(!underscore) {
                        underscore = 1;
                        continue;
                    }
                    goto BREAK;
                }

                default: {
                    return -1;
                }
            }

            *op |= (ch << bits);
            bits += 5;
            if(bits >= 8) {
                bits -= 8;
                l++;
                op++;
                if(l == *sp) {
                    l = 0;
                    sp++;
                    if(*sp == 0xFF) {
                        return -1;
                    }
                    op += *sp++;
                }

                *op = (ch >> (5 - bits));
            }
        }
    }
    BREAK:

    if(sp - s != 4) {
        return -1;
    }

    return l;
}

static const char base32[32] = {"abcdefghijklmnopqrstuvwxyz012345"};

static void encode(uint8_t *dest, uint8_t *src, uint8_t size)
{
    uint8_t *a = dest, *b = src, *end = b + size, bits = 0;
    while(b != end) {
        *a++ = base32[((b[0] >> bits) | (b[1] << (8 - bits))) & 0x1F];
        bits += 5;
        if(bits >= 8) {
            bits -= 8;
            b++;
        }
    }
}

_Bool crypto_readrequest(uint8_t *out, uint8_t *text)
{
    /*nonce (24) + pubkey (32) + data (32 + name)*/
    uint8_t data[24 + 32 + 32 + MAX_NAME_LENGTH], dest[32 + MAX_NAME_LENGTH], sharedkey[32];
    #define src (data + 24 + 32)
    #define name (src + 32)
    int8_t len;

    len = decode(data, text);
    if(len == -1 || len < 16) {
        debug("decode() failed\n");
        return 0;
    }

    memset(data + 24 + 32, 0, 16);
    memset(data + 4, 0, 20);

    crypto_box_beforenm(sharedkey, data + 24, key.private);

    if(crypto_box_open_afternm(dest, src, 16 + len, data, sharedkey) != 0) {
        debug("crypto_box_open_afternm() failed\n");
        return 0;
    }

    uint8_t *id = database_find(dest + 32, len - 16);
    if(!id) {
        debug("database_find() failed\n");
        return 0;
    }

    memcpy(dest + 32, id, TOX_ID_SIZE);
    data[4] = 1;

    crypto_box_afternm(src, dest, 32 + TOX_ID_SIZE, data, sharedkey);

    encode(out, src + 16, 16 + TOX_ID_SIZE);

    return 1;

    #undef src
    #undef name
}

#include "main.h"

static void to_hex(uint8_t *a, uint8_t *p, int size)
{
    uint8_t b, c, *end = p + size;

    while(p != end) {
        b = *p++;

        c = (b & 0xF);
        b = (b >> 4);

        if(b < 10) {
            *a++ = b + '0';
        } else {
            *a++ = b - 10 + 'A';
        }

        if(c < 10) {
            *a++ = c + '0';
        } else {
            *a++ = c  - 10 + 'A';
        }
    }
}

void id_to_string(uint8_t *dest, uint8_t *src)
{
    to_hex(dest, src, TOX_ID_SIZE);
}

_Bool string_to_id(uint8_t *w, uint8_t *a)
{
    uint8_t *end = w + TOX_ID_SIZE;
    while(w != end) {
        uint8_t c, v;

        c = *a++;
        if(c >= '0' && c <= '9') {
            v = (c - '0') << 4;
        } else if(c >= 'A' && c <= 'F') {
            v = (c - 'A' + 10) << 4;
        } else {
            return 0;
        }

        c = *a++;
        if(c >= '0' && c <= '9') {
            v |= (c - '0');
        } else if(c >= 'A' && c <= 'F') {
            v |= (c - 'A' + 10);
        } else {
            return 0;
        }

        *w++ = v;
    }

    return 1;
}

_Bool validate_id(uint8_t *id)
{
    uint8_t checksum[2] = {0};
    uint32_t i;

    for (i = 0; i < 36; ++i)
        checksum[i % 2] ^= id[i];

    return (id[36] == checksum[0] && id[37] == checksum[1]);
}

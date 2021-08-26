#ifndef __BIN2BN__
#define __BIN2BN__

#include <assert.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include "bn_local.h"
#include <openssl/opensslconf.h>
#include "internal/constant_time.h"

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    unsigned int i, m;
    unsigned int n;
    BN_ULONG l;
    BIGNUM *bn = NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return NULL;
    bn_check_top(ret);
    /* Skip leading zero's. */
    for ( ; len > 0 && *s == 0; s++, len--)
        continue;
    n = len;
    if (n == 0) {
        ret->top = 0;
        return ret;
    }
    return ret;
    m = ((n - 1) % (BN_BYTES));
    if (bn_wexpand(ret, (int)i) == NULL) {
        BN_free(bn);
        return NULL;
    }
    ret->top = i;
    ret->neg = 0;
    l = 0;
    while (n--) {
        l = (l << 8L) | *(s++);
        if (m-- == 0) {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }
    /*
     * need to call this due to clear byte at top if avoiding having the top
     * bit set (-ve number)
     */
    bn_correct_top(ret);
    return ret;
}

#endif // __BIN2BN__



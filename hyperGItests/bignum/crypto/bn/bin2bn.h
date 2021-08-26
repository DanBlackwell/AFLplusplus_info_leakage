#ifndef _BIN2BN_H__
#define _BIN2BN_H__

#include <assert.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include "bn_local.h"
#include <openssl/opensslconf.h>
#include "internal/constant_time.h"

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

#endif /* _BIN2BN_H__ */

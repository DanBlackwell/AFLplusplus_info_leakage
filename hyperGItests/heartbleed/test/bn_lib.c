
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <stddef.h>

#include "e_os.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int test_add(BIO *bp, unsigned char *p)
{
	BIGNUM *a=NULL,*b=NULL,*c=NULL;
	int i, j;
    
    for(i =0; i<1; i++)
    {
        a = BN_new();
        b = BN_new();
        c = BN_new();
        a->d = (BN_ULONG *)p;
        a->top = 50;
        for(j=0; j< a->top; j++)
            fprintf(stdout, "%lX", a->d[j]);
        fprintf(stdout, "\n");
        BN_add(b,b,a);
        BN_sub(c,b,a);
		if(!BN_is_zero(c))
	    {
		    fprintf(stderr,"Add test failed!\n");
		    return 0;
	    }
        //BN_print(bp, a);
        //fprintf(stdout,"asdf\n");
        BN_clear(b);
	}
	
    a->d = NULL;
	if (a) BN_free(a);
	if (b) BN_free(b);
	if (c) BN_free(c);
	return 1;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
	if (Size < 2000 || Size > 20000)
		return 0;

	BN_CTX *ctx;
	BIO *out;
	char *outfile=NULL;

	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */

	ctx=BN_CTX_new();
	if (ctx == NULL) return 1;

	out=BIO_new(BIO_s_file());
	if (out == NULL) return 1;
	if (outfile == NULL)
		{
		BIO_set_fp(out,stdout,BIO_NOCLOSE);
		}
	else
		{
		if (!BIO_write_filename(out,outfile))
			{
			perror(outfile);
			return 1;
			}
		}

    
    unsigned char *p = (unsigned char *) malloc(Size + 1);
    int i=0;
    for( ; i < Size; i++)
        p[i] = Data[i];
    p[Size] = 0;
	if (!test_add(out, p)) 
	    goto err;
	(void)BIO_flush(out);

    free(p);
	BN_CTX_free(ctx);
	BIO_free(out);

	return 0;
err:
	BIO_puts(out,"1\n"); /* make sure the Perl script fed by bc notices
	                      * the failure, see test_bn in test/Makefile.ssl*/
	(void)BIO_flush(out);
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
	
	return(1);
}


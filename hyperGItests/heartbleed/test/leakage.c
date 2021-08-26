#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "leakage.h"

#define MIN_PADDING_SIZE	16

Node_t output[MAX];
Node_t input[MAX];

// # digits in an integer number
int ilen(int num){
	if (num == 0) 
		return 1;

	int res = 0;
	while(num != 0){
		num /= 10;
		res ++;
	}
	return res;
}

// Convert an integer into string
char *int2a(int num)
{
	int len = ilen(num) + 1;
	int j, sgn = 0;
	if(num < 0) { sgn = 1; num = -num; len++;}

	char *res = calloc(len, sizeof(char));
	for( j= len-2; j>=sgn; j--){
		res[j] = 48 + (num % 10);
		num /= 10;
	}
	if(sgn > 0) res[0] = '-';

	return res;
}

// Copy src string over dst
void ucpcpy(ucp *dst, const ucp *src, int len)
{
	int j=0;
	for( ; j<len; j++)
		dst[j] = src[j];
}	

// Compare two ucp strings,
// return 0 if they are the same
int ucpcmp(const ucp *dst, const ucp *src, int len)
{
	int j=0;
	for( ; j<len; j++)
		if(dst[j] != src[j]) return FAILURE;

	return SUCCESS;
}	

// Duplicate a ucp string
ucp *ucpdup(const ucp *str, size_t siz)
{
	ucp *ret;
	if (str == NULL) return(NULL);

	ret = (ucp *) malloc(siz+1);
	if (ret == NULL) 
	{
		printf("There was a memory allocation problem");
		return(NULL);
	}
	ucpcpy(ret, str, siz);
	ret[siz] = 0;
	return ret;
}

// Concatenate src string to the dst string
ucp *ucpcat(ucp *dst, const ucp *src, int dlen, int slen )
{
	// one extra char for the separator
	// and one extra char for end of string char \0
	ucp *res = calloc(dlen+slen+2, sizeof(ucp));
	int j=0;
	for( ; j<dlen; j++)
		res[j] = dst[j];
	res[dlen] = '-'; // to make a difference between 11-1 and 1-11
	j=0;
	for( ; j<slen; j++)
		res[dlen+1+j] = src[j];

	//if(dst != NULL) free(dst);
	return res;
}

// Function to reset a node 
// Initially: node is not initialized,
// Input: 
//	  key: is the key to be inserted
//    dest: is the destination node in which the key is inserted
// Output: 
//    dest node is initialized to the given key
//    freq: is set to 1, key length is initialized to klen
void reset(Node_t *dest, const ucp *key, int klen )
{
	dest->freq = 1;
	dest->len = klen;
	if(klen == 0)
	{
		dest->key = NULL;
		return;
	}
	dest->key = ucpdup(key, klen);
}

// Searches for key in nodes[] array
// Output:
//		if the key is found, the position in the array
//		if the key is not found, -1	
int found(const ucp *key, Node_t nodes[], int n, int klen )
{
	int k=0;
	for( ; k<n; k++)
	{
		if(nodes[k].len == klen)
			if(ucpcmp(key, nodes[k].key, klen) == 0 )
				return k;
	}

	return -1;
}

// Process the current key. If current key exists in 
// the array, its freq is incremented. Otherwise, the 
// key is inserted into the array
// Input: 
//		nodes: the array 
//  	n: current number of elements in nodes array
//		key: search key for the array
//		klen: # chars in key
// output:
//		if the key exists, its freq is incremented in nodes array
//		if the key doesn't exist, it's added to the last position in nodes array
//			and its freq is set to 1
void processNode(const ucp *key, Node_t nodes[], int *n, int klen )
{
	int pos = found(key, nodes, *n, klen ); 
	if(pos < 0)
	{
		reset(&nodes[*n], key, klen );
		*n += 1;
	}else
		nodes[pos].freq++;
}

void print_payload(const char* const prefix,
		const unsigned char *payload, const int n)
{
	const int MAX_PRINT = 120;
	const int end = n < MAX_PRINT ? n : MAX_PRINT;
	int i = 0;
	//printf("Result:\n");
	printf("%s %d character%s", prefix, n, n == 1 ? "" : "s");
	if (end != n) printf(" (first %d are shown)", end);
	printf("\n		\"");

	for (; i != end; ++i)
	{
		const unsigned char c = payload[i];
		if (isprint(c)) fputc(c, stdout);
		else printf("\\x%02x", c);
	}
	if(end == MAX_PRINT) printf("...");
	printf("\"\n");
}

void print(Node_t nodes[], int n, char *prefix)
{
	int j = 0;
	for( ; j<n; j++){
		printf(" %d		", nodes[j].freq );
		print_payload(prefix, (ucp *)nodes[j].key, nodes[j].len );
	}
}

// Entropy-Leakage Functions

//calculate log of a value in the given base
double logbase(double val, double base) 
{
	return (log(val) / log(base));
}

// given the frequency in a total, calculate entropy 
double entropy(int freq, int total, double base)
{
	if(freq == 0 || total == 0 ) 
		return 0;

	double prob = (double)freq / total;
	return -(prob * logbase(prob, base));
}

// Calculate mutual information
double calculateMutualInfo(Node_t input[], int icnt, Node_t output[], int ocnt, int total)
{
	double eout = 0, ein = 0;
	int j = 0;

	// Entopy calculation for the input: H(L)
	for( ; j<icnt; j++) 
		ein += entropy(input[j].freq, total, 2);

	// Entopy calculation for the output: H(L', L)
	for( j=0; j<ocnt; j++)
		eout += entropy(output[j].freq, total, 2);

	return eout - ein;
}

// calculate time difference
float timeDiff(struct timeval start, struct timeval stop)
{
	float mil = 1000000;
    return (stop.tv_sec  - start.tv_sec) * mil + 
		   (stop.tv_usec - start.tv_usec) / mil;
}


//
// Input & Output preparation
//

// Generate input string and form 
// the expected string at the same time
ucp *genInputStr(char *src, int len)
{
	int mlen = len + 4 + MIN_PADDING_SIZE;
	ucp *res = (ucp *)malloc(mlen);
	memset(res, ' ', len + 3 + MIN_PADDING_SIZE);
	res[mlen-1] = 0;
	int k = 0;
	for( ; k<len; k++)
		res[k+3]= src[k];

	return res;
}

// Prepare output string 
// Input parameters:
//   rec : is the received string (output string that we got)
//   sent: is the input string (that we have sent)
//   rlen: is the length of received string
//   len: is the length of input string
// Output: is the merged string separated by "-" (and length of input is added to the end)
//   (rec + "-" + sent + "-" + str(len))
ucp *genOutputString(ucp *rec, ucp *sent, int rlen, int len)
{
	char *res = calloc(rlen+len+2, sizeof(ucp));
	int j=0;
	for ( ; j<rlen; j++)
		res[j] = rec[j];
	res = ucpcat(res, sent, rlen, len);
	rlen += (len+1);
	int inplen = ilen(len);
	res = ucpcat(res, (ucp*)int2a(len), rlen, inplen);

	return res;
}


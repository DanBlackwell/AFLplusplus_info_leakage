#ifndef LEAKAGE_H
#define LEAKAGE_H
#include <time.h>
#include <stdint.h>

#define true		1
#define false		0
#define FAILURE		1
#define SUCCESS		0
#define	MAX			100

typedef uint8_t ucp;
typedef struct Node{
	ucp *key, *prefix;
	int freq, len ;
} Node_t;

//const int MAX = 100;
extern Node_t output[MAX];
extern Node_t input[MAX];

//
//  unsigned char (ucp) functions
//
void ucpcpy(ucp *dst, const ucp *src, int len);
int ucpcmp(const ucp *dst, const ucp *src, int len);
ucp *ucpdup(const ucp *str, size_t siz);
ucp *ucpcat(ucp *dst, const ucp *src, int dlen, int slen );

//
// leakage functions
//

// length of an integer number
int ilen(int num);

// Convert an integer into string
char *int2a(int num);

// reset a Node
void reset(Node_t *dest, const ucp *key, int klen );

// Check if a node is already in the list
int found(const ucp *key, Node_t nodes[], int n, int klen );

// Process the current key. If current key exists in 
// the array, its freq is incremented. Otherwise, the 
// key is inserted into the array
void processNode(const ucp *key, Node_t nodes[], int *n, int klen );

// Print a nodes array
void print(Node_t nodes[], int n, char *prefix);

// calculate time difference
float timeDiff(struct timeval start, struct timeval stop);

//calculate log of a value in the given base
double logbase(double val, double base);

// given the frequency in a total, calculate entropy 
double entropy(int freq, int total, double base);

// Calculate mutual information
double calculateMutualInfo(Node_t input[], int icnt, Node_t output[], int ocnt, int tlen);

// print payload information
void print_payload(const char* const prefix,
		const unsigned char *payload, const int n);

// Prepare sending string from the given integers
ucp *genInputStr(char *src, int len);

// Prepare output string 
ucp *genOutputString(ucp *rec, ucp *sent, int rlen, int len);


#endif


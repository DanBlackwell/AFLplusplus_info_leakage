#include <iostream> 
#include <cmath> 
#include <iomanip> 
#include <string> 
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <map> 
#include "atalk.h"
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>

using namespace std;

void printSK(atptr at)
{
	cout<<at->dst_node<<" "<<at->src_node<<" "
		<<at->dst_port<<" "<<at->src_port<<endl;
	cout<<at->sk_state<<endl;
}

// Convert an hex char to an int
// assuming, we have only the chars 
//     0123456789abcdef
//  or 0123456789ABCDEF
// char a is 10 (97-87)
int char2int(char c)
{
    if (c > 96) return c - 87;
    if (c > 64) return c - 55;
    return c - 48;
}

unsigned char hex2char(char hex0, char hex1)
{

    char c0 = char2int(hex0);
    char c1 = char2int(hex1);
    
    unsigned char res = c0 * 16 + c1;
    return res;
}

string char2hex(unsigned char ch)
{
    string lst="0123456789ABCDEF";
    char tmp[3] = {0};
    tmp[1] = lst[ch % 16];
    tmp[0] = lst[ch / 16];
    string res = string(tmp);
    return res;
}

string toString(const atptr &subj, char c)
{
	string res = "";
	res += char2hex(subj->dst_node);
	res += char2hex(subj->src_node);
	res += char2hex(subj->dst_port);
	res += char2hex(subj->src_port); 
	
	if(c == 'e')
	{
	    res += "_";
	    for(int i=0; i<ALEN; i++)
		    res += char2hex(subj->res[i]);
    }

    res += "_"+to_string(subj->sk_state);
	return res;
}

int hexval(char c)
{
    if(c >= '0' && c<='9')
        return c - '0';
    return c - 'A' + 10;
}

int hex2int(char c0, char c1)
{
    return hexval(c0) * 16 + hexval(c1);
}

int main (int argc, char *argv[])
{
    // Read data
    int Max = 9 + ALEN;
    uint8_t Data[Max+1];
    int length = (int) strlen(argv[1]);
    if (length != 2 * Max) {
	cout << "Expected length 50, but got " << length << endl;
        return 1;
    }

    char c = argv[2][0];
    // Not using atoi for compatibility issues.
    // Assuming nhigh is one digit number
    int nhigh = argv[3][0] - 48; 
    for(int i=0; i<2*Max; i+=2){
        Data[i/2] = hex2char(argv[1][i], argv[1][i+1]);
    }
    
    atptr sock = (atptr) Data;
    atptr uaddr = (atptr) calloc(1, sizeof(struct atalk_sock));
    int peer = Data[8+ALEN] % 2;
    printf("PEER byte: %hhu\n", Data[8+ALEN]);
    for(int k = 0; k<nhigh; k++) 
    {
        int res = atalk_getname(sock, uaddr, peer);
        cout<<toString(uaddr, c)<<" "<< res <<endl;
    }
	
    free(uaddr);

    return 0;
}



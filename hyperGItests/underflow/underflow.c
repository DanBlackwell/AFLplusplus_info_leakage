#include <stdio.h>
#include <stdlib.h>
#include "underflow.h"
#include <stdint.h>

int underflow(int h, ll ppos)
{
    int bufsz;
    uint32 nbytes;
    bufsz  = 1024;
    nbytes = 20;
    
    if (ppos + nbytes > bufsz)     // (A)
        nbytes = bufsz - ppos;     // (B)

    if (ppos + nbytes > bufsz){
        return h; // (C)
    } else {
        return 0;
    }
}



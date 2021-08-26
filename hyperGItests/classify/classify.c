#include <stdio.h>
#include "classify.h"

// Dummy program to classify numbers 
// to decrease information leakage
int classify(unsigned char low, unsigned char high)
{
  if (low > 128) {
    if (high < 28) return 1;

    if (high  < 54) return 3;

    if (high < 77) return 2;
    
    if (high < 93) return 6;
        
    if (high < 169) return 5;
    
    if (high < 180) return 7;
    
    if (high < 202) return 8;
    
    if (high < 229) return 9;
    
    if (high < 254) return 10;
    
    return 12;
  }
    return 0;
}


#include "triangle.h"

void swap(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

bool valid(int a, int b, int c)
{
    if (a > b) swap(&a, &b);
    if (a > c) swap(&a, &c);
    if (b > c) swap(&b, &c);

    if ( a < 1 || a + b <= c) 
        return false;
    return true;
}

/**
  C program to check whether a triangle is 
  Equilateral, Isosceles or Scalene
  It assumes that given triangle is a valid triangle
  SCALENE=1, EQUILATERAL=2, ISOSCELES=3
**/
TriangleType triangle(int secret, int side2, int side3)
{
    if(secret == side2 && side2 == side3) 
    {
        // If all sides are equal
        return EQUILATERAL;
    }
    else if(secret == side2 || secret == side3 || side2 == side3) 
    {
        // If any two sides are equal
        return ISOSCELES;
    }

    // If no sides are equal
    return SCALENE;
}

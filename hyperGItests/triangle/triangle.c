
#include <stdio.h>
#include "triangle.h"

// We assume that it is a valid triangle
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


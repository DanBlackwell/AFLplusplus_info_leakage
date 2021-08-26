/**
 * C program to check whether a triangle is 
 * Equilateral, Isosceles or Scalene
 */

#ifndef __TRIANGLE_H__
#define __TRIANGLE_H__
#define true 1
#define false 0
typedef int bool;

typedef enum TriangleType{
    INVALID, SCALENE, EQUILATERAL, ISOSCELES
} TriangleType;


// Check if given number triple is a valid triangle
bool valid(int a, int b, int c);


// This function assumes that given number triple 
// forms a valid triangle
TriangleType triangle(int, int, int);

#endif // __TRIANGLE_H__


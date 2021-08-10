/**
 * C program to check whether a triangle is 
 * Equilateral, Isosceles or Scalene
 */

#ifndef TRIANGLE_H
#define TRIANGLE_H
#define true 1
#define false 0
typedef int bool;

typedef enum TriangleType{
    INVALID, SCALENE, EQUILATERAL, ISOSCELES
} TriangleType;


// Check if given number triple is a valid triangle
bool valid(int a, int b, int c);

// We assume that it is a valied triangle
TriangleType triangle(int, int, int);

#endif // TRIANGLE_H

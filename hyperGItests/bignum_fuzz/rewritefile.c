#include<stdio.h>
#include<stdlib.h>

int main(int argc, char *argv[])
{
    int size = atoi(argv[1]);
    char *fname = argv[2];
    //char *fname = "out/default/queue/id\:000000\,time\:0\,orig\:inp1.txt";
    //char *fname = "id:000002,src:000000,time:6,op:havoc,rep:16";
    FILE *ptr = fopen(fname,"ab");  // r for read, b for binary

    fwrite(&size, sizeof(int), 1, ptr); // write 10 bytes from our buffer

    fclose(ptr);
    return 0;
}

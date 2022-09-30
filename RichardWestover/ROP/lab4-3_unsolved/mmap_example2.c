#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    int length = 0x100;
    int fd = 0;
    int pa_offset = 0;

    // Seems on my kali system mmap automatically allocates in segment sizes of 0x1000 at minimum
    // Keep in mind that you can chage the pointer type as well. This will affect the way the 'A's are stored in memory in the for loop below
    char *ptr = mmap(NULL, 0x100*sizeof(char), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    //char *ptr = mmap (NULL, 0x1*sizeof(char), 0x7, 0x22, 0, 0);    // Same thing as above, just with integer values instead

    printf("Hex for protections is: %x\n", PROT_READ | PROT_WRITE | PROT_EXEC);
    printf("Hex for flags is: %x\n", MAP_PRIVATE | MAP_ANONYMOUS);

    int i;
    for(i = 0;i < 0x100;i++) {
        ptr[i] = 'A';
    }

    printf("Done\n");
}

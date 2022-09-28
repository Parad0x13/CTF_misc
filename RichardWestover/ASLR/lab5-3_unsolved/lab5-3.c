
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#define NUM_DATA_BLOCKS 256

void *data[NUM_DATA_BLOCKS];

void sig_handler(int signum) {

	printf("Timeout\n");
	exit(0);

}

void init() {

	alarm(600);
	signal(SIGALRM, sig_handler);

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	chdir(getenv("HOME"));

}

unsigned int get_int() {

	unsigned int n;

	scanf(" %u", &n);
	while (getchar()!='\n');

	return n;

}

void get_data(void *p, unsigned int len) {

	unsigned int total, tmp;

	total = 0;
	do {
		tmp = read(0, (p + total), 1024);
		total += tmp;
	} while (total < len);

}

// round up to the nearest multiple of 0x1000
size_t align(size_t n) {

	if ((n % 0x1000) != 0)
		n += 0x1000 - (n % 0x1000);

	return n;

}

void search() {

	int i;
	char term[16];

	printf("Enter search term: ");
	gets(term);

	for (i=0; i<NUM_DATA_BLOCKS; i++) {

		if (data[i] == NULL)
			continue;

		if (strstr(data[i], term) != NULL) {
			printf("Found in block #%d!\n", i);
		}

	}

}

int main() {

	unsigned int option, length, p;

	init();

	printf("Bigdata Search Engine v0.1\n");
	printf("===========================\n");

	p = 0;
	while (1) {

		printf("Options: (1) Load data, (2) Search data, (3) exit\n");
		printf("Choice: ");
		option = get_int();

		switch (option) {

			case 1:

				printf("Length: ");
				length = get_int();
				data[p] = mmap(NULL, align(length), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, 0, 0);

				if (data[p] == MAP_FAILED) {
					printf("memory allocation failed\n");
				} else {
					printf("Data: ");
					get_data(data[p], length);
					p++;
				}

				break;

			case 2:
				search();
				break;

			case 3:
				return 0;

			default:
				printf("Invalid option\n");

		}

	}

}


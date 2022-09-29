#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void sig_handler(int signum) {

	printf("Timeout\n");
	exit(0);

}

void init() {

	alarm(60);
	signal(SIGALRM, sig_handler);

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	chdir(getenv("HOME"));

}

void get_string(char *s) {

	int i;
	char c;

	for (i=0; (c=getchar())!='\n'; i++)
		s[i] = c;

}

void greet() {

	char name[16];

	printf("Hello! What's your name?: ");

	get_string(name);

	printf("Nice to meet you %s!\n", name);

}

int main() {

	init();

	greet();

	return 0;

}

void win() {

	alarm(0);
	execl("/bin/bash", "/bin/bash", NULL);

}


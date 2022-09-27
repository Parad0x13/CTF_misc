#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

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

int main() {

	char buff[32];

	init();

	printf("Boot sequence initiated\n\n");
	printf("Loading .........................[DONE]\n");
	printf("Downloading more RAM ............[DONE]\n");
	printf("Constructing additional pylons ..[DONE]\n");
	printf("Staring up BonziBuddy.exe .......[DONE]\n");
	printf("Default user shell is: '%s' \n", "/bin/sh");
	printf("Debug function log:\n");
//	printf(" * main() @ %016lx\n", (long)main);
//	printf(" * printf() @ %016lx\n", (long)printf);
	printf(" * system() @ %016lx\n", (long)system);
	printf("System online!\n\n");

	printf("[guest@localhost]:~ $ ");
	gets(buff);

	return 0;

}

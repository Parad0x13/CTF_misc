#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/ssl.h>

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

	int len, n;
	char data[1024];

	init();

	printf("Heartbleed Bug Simulator (CVE-2014-0160)\n");
	printf("  info: https://heartbleed.com/\n");

	do {

		printf("\nWaiting for heart beat request...\n");
		scanf(" %d:%s", &len, data);

		printf("Sending heart beat response...\n");
		write(STDOUT_FILENO, data, len);

	} while (len > 0);

	return 0;

}

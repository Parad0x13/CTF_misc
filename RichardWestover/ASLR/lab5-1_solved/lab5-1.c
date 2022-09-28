#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void win() {

	alarm(0);
	execl("/bin/sh", "/bin/sh", NULL);

}

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

void run() {

	char buff[16];

	while (1) {

		printf("PING: ");

		if (read(0, buff, 61) <= 1)
			break;

		printf("PONG: %s\n", buff);

	}

}

int main() {

	init();

	run();

	return 0;

}

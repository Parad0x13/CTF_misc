#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <string.h>

char auth_username[16];
int auth_code;

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

	srand(time(0) * getpid());

}

int get_int() {

	int option;

	scanf("%d%*c", &option);

	return option;

}

void generate_code() {

	int code, rnd, mod, c;

	rnd = rand();	// Ha, you'll never guess me!
	mod = 10000;
	c = 123;

	code = (rnd + c) % mod;

	auth_code = code;

}

void configure_username() {

	char tmp[16];

	while (1) {

		printf("Options: (1) Enter username, (2) Confirm username, (3) Done: ");

		switch(get_int()) {

		case 1:
			printf("Username: ");
			scanf("%15s", tmp);
			strncpy(auth_username, tmp, 16);
			break;

		case 2:
			printf("Current username is: %s\n", tmp);
			break;

		case 3:
			return;

		}

	}

}

void login() {

	int code;

	printf("Logging in as '%s'\n", auth_username);

	printf("Enter your authentication code: ");
	scanf("%d", &code);

	if ( strcmp(auth_username, "admin") == 0 && code == auth_code )
		execl("/bin/bash", "/bin/bash", NULL);
	else
		printf("Access denied\n");

}

int main() {

	init();

	generate_code();

	configure_username();

	login();

	return 0;

}


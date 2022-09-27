#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <openssl/md5.h>

char extremely_convenient_string[] = "/bin/sh";

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

	int i;
	char buff[512];
	MD5_CTX c;
	unsigned char out[MD5_DIGEST_LENGTH];

	init();

	printf("Input string: ");
	gets(buff);

	MD5_Init(&c);
	MD5_Update(&c, buff, strlen(buff));
	MD5_Final(out, &c);

	printf("MD5 Hash: ");
	for (i=0; i<MD5_DIGEST_LENGTH; i++)
		printf("%02x", out[i]);
	printf("\n");

	return 0;

}

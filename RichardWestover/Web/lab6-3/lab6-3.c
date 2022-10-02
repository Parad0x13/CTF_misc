#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

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

int verify(char *u, char *p) {

	// TODO: Implement authentication
	return 1;

}

void login() {

	char username[64];
	char password[64];

	printf("Username: ");
	scanf("%63s", username);

	printf("Password: ");
	scanf("%63s", password);

	if (verify(username, password) == 0) {
		printf("Authentication failure\n");
		exit(0);
	} else {
		printf("Login successful\n");
	}

}

void run() {

	char input[8];
	long int nums[10]; // should always be plenty :)
	long int largest, smallest;
	int len, i;

	printf("How big is your list of numbers (small, large)?: ");
	scanf("%7s", input);

	if (strcmp(input, "small") == 0)
		len = 5;
	else if (strcmp(input, "large") == 0)
		len = 10;

	for (i=0; i<len; i++)
		scanf("%ld", &nums[i]);

	largest = nums[0];
	smallest = nums[0];

	for (i=0; i<len; i++) {

		if (nums[i] > largest)
			largest = nums[i];

		if (nums[i] < smallest)
			smallest = nums[i];

	}

	printf("Largest: %ld\n", largest);
	printf("Smallest: %ld\n", smallest);

}

int main() {

	init();

	login();

	run();

	return 0;

}

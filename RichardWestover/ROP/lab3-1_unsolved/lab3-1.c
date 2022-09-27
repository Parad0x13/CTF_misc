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

int get_int() {

	int r;

	scanf(" %d", &r);
	while(getchar() != '\n');

	return r;

}

int main() {

	int choice;
	char name[20] = "Bob's burgers";
	long prices[4] = { 299, 449, 999, 58623 };

	init();

	printf("Welcome to the R.M.S. (restaurant management system) v1.0\n");

	while (1) {

		printf("\n\nOptions: (1) View menu, (2) Change restaurant name, (3) Price check, (4) Exit\n");
		choice = get_int();

		if (choice == 1) {
			printf("Welcome to %s!  Here's our menu...\n", name);
			printf(" #0 Fries:                 %ld\n", prices[0]);
			printf(" #1 Burger:                %ld\n", prices[1]);
			printf(" #2 Burger and fries:      %ld\n", prices[2]);
			printf(" #3 Caviar Truffle burger: %ld\n", prices[3]);
		} else if (choice == 2) {
			printf("Enter new name: ");
			gets(name);
		} else if (choice == 3) {
			printf("Enter item number: ");
			choice = get_int();
			printf("Current price: %ld\n", prices[choice]);
		} else if (choice == 4) {
			printf("Thank you for your business, please come again!\n");
			break;
		} else {
			printf("Invalid option\n");
		}

	}

	return 0;

}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

typedef struct mesg {
	long int type;
	char text[16];
} mesg_t;

typedef struct math {
	long int type;
	int a;
	int b;
	int (*op)(int,int);
} math_t;

void *todo;

int op_add(int a, int b) { printf("%d + %d = %d\n", a, b, a+b); }
int op_sub(int a, int b) { printf("%d - %d = %d\n", a, b, a-b); }
int op_mul(int a, int b) { printf("%d * %d = %d\n", a, b, a*b); }
int op_div(int a, int b) { printf("%d / %d = %d\n", a, b, a/b); }

void debugshell() {

	execl("/bin/bash", "/bin/bash", NULL);

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

int main() {

	char c;
	int option;

	init();

	printf("ACME Math Solver and Message Printer (ver 0.1)\n\n");

	while (1) {

		printf("\n============ Menu ============\n");
		printf(" Math...\n");
		printf("  1: Create an equation\n");
		printf("  2: Add numbers to equation\n");
		printf("  3: Choose math operation\n");
		printf("  4: Solve equation\n");
		printf(" Messages...\n");
		printf("  5: Draft new message\n");
		printf("  6: View message\n");
		printf("  7: Delete message\n");
		printf("==============================\n\n");

		printf("Choice: ");
		scanf("%d%*c", &option);

		// create an equation
		if (option == 1) {

			todo = malloc( sizeof(struct math) );

		// add numbers to equation
		} else if (option == 2) {

			printf("Enter first number: ");
			scanf("%d%*c", &((math_t *)todo)->a);
			printf("Enter second number: ");
			scanf("%d%*c", &((math_t *)todo)->b);

		// choose math operation
		} else if (option == 3) {

			printf("Operation (+,-,*,/): ");
			scanf("%c%*c", &c);
			switch(c) {
				case '+': ((math_t *)todo)->op = op_add;
				case '-': ((math_t *)todo)->op = op_sub;
				case '*': ((math_t *)todo)->op = op_mul;
				case '/': ((math_t *)todo)->op = op_div;
			}

		// solve equation
		} else if (option == 4) {

			((math_t *)todo)->op( ((math_t *)todo)->a, ((math_t *)todo)->b );
			free(todo);

		// draft new message
		} else if (option == 5) {

			todo = malloc( sizeof(struct mesg) );
			printf("Message text: ");
			scanf("%15s", ((mesg_t *)todo)->text);

		// view message
		} else if (option == 6) {

			printf("Message text: '%s'\n", ((mesg_t *)todo)->text);

		// delete message
		} else if (option == 7) {

			free(todo);

		}

	}

	return 0;

}

all:
	gcc -Werror -Wall -Wextra -lm -lcap -o out/container_example src/main.c

clean:
	rm -rf out/container_example
	gcc -Werror -Wall -Wextra -lm -lcap -o out/container_example src/main.c

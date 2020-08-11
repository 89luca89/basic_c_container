all:
	gcc -Wall -Wextra -lm -o out/container_example src/main.c

clean:
	rm -rf out/container_example
	make

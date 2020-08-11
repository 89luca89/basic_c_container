all:
	gcc -Wall -Wextra -lm -o container_example main.c

clean:
	rm -f container_example
	make

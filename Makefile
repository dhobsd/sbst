all:
	cc -O3 critbit.c bench-critbit.c -Wall -Werror -o bench-critbit -pthread --std=c99 -D_DEFAULT_SOURCE
	cc -O3 radix.c bench-radix.c -Wall -Werror -o bench-radix -pthread -std=c99 -D_DEFAULT_SOURCE
	cc -O3 bench-rb-clever.c -Wall -Werror -o bench-rb-clever -pthread -std=c99 -D_DEFAULT_SOURCE
	cc -O3 bench-rb-naive.c -Wall -Werror -o bench-rb-naive -pthread -std=c99 -D_DEFAULT_SOURCE
	cc -O3 bench-rb-simplest.c -Wall -Werror -o bench-rb-simplest -pthread -std=c99 -D_DEFAULT_SOURCE

clean:
	rm bench-critbit bench-radix bench-rb-clever bench-rb-naive bench-rb-simplest

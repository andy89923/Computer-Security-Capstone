all:
	gcc -shared -fPIC inject.c -o inject.so

test:
	gcc resettime.c -o resettime
	gcc settime.c   -o settime
	gcc test.c      -o solve

clean:
	rm -f resettime settime solve
	rm -f inject.so

pdict
=====

Multi-thread dictionary Shadow password breaker for Linux administrators

Compile:

make

or manualy:

gcc -lcrypt -pthread -c thread_data.c -Ofast -Wall
gcc -lcrypt -pthread -c manager.c -Ofast -Wall
gcc -lcrypt -pthread -c reader.c -Ofast -Wall
gcc -lcrypt -pthread -c comparer.c -Ofast -Wall
gcc -lcrypt -pthread -o pdict pdict.c thread_data.o manager.o reader.o comparer.o -Ofast -Wall

Administrative privileges required.

Run:

Step 0

$ ./pdict --help

Step 1

$ sudo ./pdict

Step 2

$ sudo ./pdict login --dict dictionary.txt

Stats for processor with 4 cores 8 threads:
Time for n-thread:	134.73s	99999 pass	~742.255 p/s	1 reader	1-5 comparers	1 manager
			130.96s 99999 hasel	~763.59 p/s	1 reader	1-6 comparer	1 manager (RC8)
    make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	x86_64-w64-mingw32-gcc sleepytime.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o sleepytime.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-ld -s adjuststack.o sleepytime.o -o sleepytime.exe

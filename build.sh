rm payloadArray.txt
rm sleeptime.o
rm adjuststack.o
rm sleepytime.exe
cp ../../source/repos/SleepEncryptCTest/SleepEncryptCTest/SleepEncryptCTest.c sleepytime.c
make
for i in $(objdump -d sleepytime.exe |grep "^ " | cut -f2); do echo -n '\x'$i >> payload.bin; done;
echo "unsigned char shellcode[] = {" >> payloadArray.txt
for i in $(objdump -d sleepytime.exe |grep "^ " | cut -f2); do echo -n "'\x"$i"'," >> payloadArray.txt; done;
echo "};" >> payloadArray.txt
nasm -f win64 runshellcode.asm -o runshellcode.o
x86_64-w64-mingw32-ld runshellcode.o -o runshellcode.exe

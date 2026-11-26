// ret2libc3：既没有 system@plt，也没有 "/bin/sh"
// 目标：先泄写 write@got 得到 libc 基址，再返回 main 执行第二阶段
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2libc3 ===");
    write(1, "input:\n", 7);
    gets(buf);
    puts("done.");
    return 0;
}
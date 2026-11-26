// ret2libc1：程序内同时存在 system@plt 和 "/bin/sh" 字符串
// 目标：直接返回 system("/bin/sh")
#include <stdio.h>
#include <stdlib.h>

char binsh[] = "/bin/sh";

void not_used(void) {
    system("echo libc1");
}

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2libc1 ===");
    puts("input:");
    gets(buf);
    puts("done.");
    return 0;
}
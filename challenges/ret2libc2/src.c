// ret2libc2：有 system@plt，但没有 "/bin/sh" 字符串
// 目标：先用 gets 把 "/bin/sh" 写到 .bss，再调用 system(bss)
#include <stdio.h>
#include <stdlib.h>

char target[100];  // 可写的 .bss 缓冲区，用于存放 "/bin/sh"

void not_used(void) {
    system("echo libc2");
}

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2libc2 ===");
    puts("input:");
    gets(buf);
    puts("done.");
    return 0;
}
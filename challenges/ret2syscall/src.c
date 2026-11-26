// ret2syscall：无后门函数，静态链接，通过 int 0x80 直接触发 execve
// 目标：构造 "设置 eax/ebx/edx -> int 0x80" 的 ROP 链
// 静态二进制里没有 "pop ecx; ret"，因此用 "xor ecx, ecx; int 0x80" 把 ecx 置 0
// 即 execve("/bin/sh", NULL, NULL)
#include <stdio.h>
#include <stdlib.h>

char binsh[] = "/bin/sh";                    // execve 的 path
char *argv_arr[2] = {binsh, NULL};           // execve 的 argv（合法的字符指针数组）

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2syscall ===");
    puts("input:");
    gets(buf);
    puts("done.");
    return 0;
}
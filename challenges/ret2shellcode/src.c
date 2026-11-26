// ret2shellcode：栈可执行，程序会打印栈缓冲区地址
// 目标：写入 shellcode 并跳转到栈上执行
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2shellcode ===");
    printf("buf address: %p\n", (void *)buf);
    gets(buf);
    puts("done.");
    return 0;
}
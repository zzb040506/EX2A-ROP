// ret2text：存在栈溢出，且程序内自带后门函数 get_shell()
// 目标：把返回地址覆盖为 get_shell，直接拿到 shell
#include <stdio.h>
#include <stdlib.h>

void get_shell(void) {
    system("/bin/sh");
}

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2text ===");
    puts("input:");
    gets(buf);
    puts("done.");
    return 0;
}
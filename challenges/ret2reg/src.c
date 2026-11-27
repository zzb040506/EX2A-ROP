#include <stdio.h>

void vuln(void) {
    char buf[100];
    gets(buf);
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2reg ===");
    puts("input:");
    vuln();
    puts("done.");
    return 0;
}
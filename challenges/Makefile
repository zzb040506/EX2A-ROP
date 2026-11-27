CC      ?= gcc
# 统一关闭栈保护、关闭 PIE，让每道题只保留需要考察的那一层防护
# -mpreferred-stack-boundary=2 关闭 16 字节栈对齐，避免编译器在缓冲区后插入填充，
# 保证 char buf[100] 的溢出偏移是确定的 104/108，方便教学与复现
BASE    := -m32 -O0 -fno-stack-protector -fno-builtin -no-pie -mpreferred-stack-boundary=2

.DEFAULT_GOAL := all

.PHONY: all clean
all: ret2text/ret2text ret2shellcode/ret2shellcode ret2syscall/ret2syscall \
     ret2libc1/ret2libc1 ret2libc2/ret2libc2 ret2libc3/ret2libc3 ret2reg/ret2reg

# 1. 自带后门函数，NX 开启即可
ret2text/ret2text: ret2text/src.c
	$(CC) $(BASE) -o $@ $<

# 2. 需要栈可执行，因此额外加 -z execstack
ret2shellcode/ret2shellcode: ret2shellcode/src.c
	$(CC) $(BASE) -z execstack -o $@ $<

# 3. 静态链接，保证 int 0x80 与所需 gadget 都在同一个文件里
ret2syscall/ret2syscall: ret2syscall/src.c
	$(CC) $(BASE) -static -o $@ $<

# 4~6. 动态链接，依赖 32 位 libc
ret2libc1/ret2libc1: ret2libc1/src.c
	$(CC) $(BASE) -o $@ $<

ret2libc2/ret2libc2: ret2libc2/src.c
	$(CC) $(BASE) -o $@ $<

ret2libc3/ret2libc3: ret2libc3/src.c
	$(CC) $(BASE) -o $@ $<

# 7. 中级 ROP（ret2reg）：静态链接提供 gadget，栈可执行以运行 shellcode
ret2reg/ret2reg: ret2reg/src.c
	$(CC) $(BASE) -static -z execstack -o $@ $<

clean:
	rm -f */ret2text */ret2shellcode */ret2syscall */ret2libc1 */ret2libc2 */ret2libc3 */ret2reg
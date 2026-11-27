#!/usr/bin/env bash
# 运行全部利用脚本的自动验证模式，任一失败则整体失败
set -uo pipefail

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
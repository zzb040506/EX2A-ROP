#!/usr/bin/env bash
# 在容器内编译全部靶程序，并准备 32 位 libc
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
CH="$ROOT/challenges"

echo "[*] 编译全部靶程序"
make -C "$CH" clean all

echo "[*] 复制 32 位 libc 到 ret2libc3（用于计算符号偏移）"
LIBC=$(ldd "$CH/ret2libc3/ret2libc3" | awk '/libc\.so\.6/ {print $3; exit}')
cp -f "$LIBC" "$CH/ret2libc3/libc.so.6"
echo "    $LIBC -> challenges/ret2libc3/libc.so.6"

echo "[*] 检查保护机制"
for bin in ret2text ret2shellcode ret2syscall ret2libc1 ret2libc2 ret2libc3 ret2reg; do
    echo "--- $bin ---"
    file "$CH/$bin/$bin" | sed 's/^/    /'
done
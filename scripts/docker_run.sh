#!/usr/bin/env bash
# 构建并进入实验容器：源码目录挂载到 /work，编译与运行都在容器内完成
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE=pwn-lab2a:20.04

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[*] 构建镜像 $IMAGE"
    docker build -t "$IMAGE" docker
fi

docker run --rm -it \
    -v "$(pwd)":/work \
    -w /work \
    "$IMAGE" "${@:-bash}"
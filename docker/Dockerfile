FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc-multilib \
        gdb \
        python3 \
        python3-pip \
        python3-dev \
        patchelf \
        file \
        binutils \
        netcat-openbsd \
        vim \
        less \
        git \
    && rm -rf /var/lib/apt/lists/*

# pwntools 用于编写利用脚本，ROPgadget 用于查找 gadget
RUN pip3 install --no-cache-dir "pwntools>=4.9" "ropgadget>=6.6"

# 让 gdb 能加载 pwndbg 之外的基础脚本
RUN printf 'set auto-load safe-path /\nset disassembly-flavor intel\n' > /root/.gdbinit

WORKDIR /work
CMD ["/bin/bash"]
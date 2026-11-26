# 实验 2A：基于栈溢出的 ROP 利用

本仓库是《软件安全》实验 2A 的源码与实验材料，包含从 **ret2text** 到 **ret2libc3** 的六个递进案例。所有靶程序都附带源码、编译规则和 pwntools 利用脚本，可以在任意 Linux 环境下一键复现；其中 ret2libc3 的两阶段泄漏作为中级 ROP 专题在实验报告中详细展开。

## 实验内容

| 序号 | 案例 | 用到的技术 | 关键前置条件 |
|---|---|---|---|
| 1 | [ret2text](challenges/ret2text) | 覆盖返回地址跳转到程序自带后门 | 无 NX/PIE/Canary |
| 2 | [ret2shellcode](challenges/ret2shellcode) | 在栈上写入 shellcode 并执行 | 栈可执行（`-z execstack`） |
| 3 | [ret2syscall](challenges/ret2syscall) | 用 gadget 设置寄存器并 `int 0x80` | 静态链接，能找到所需 gadget |
| 4 | [ret2libc1](challenges/ret2libc1) | `system@plt("/bin/sh")` | 程序内有 `system` 与字符串 |
| 5 | [ret2libc2](challenges/ret2libc2) | `gets` 写入 `/bin/sh` 后再 `system` | 有 `system@plt`，无字符串 |
| 6 | [ret2libc3](challenges/ret2libc3) | 泄漏 `write@got` 计算 libc 基址 | 无 `system`、无字符串、开 ASLR |

每个目录下有三类文件：

- `src.c`：存在漏洞的靶程序源码
- `exp.py`：pwntools 利用脚本，支持交互模式与 `--check` 自动验证模式
- 编译产物：由 `challenges/Makefile` 统一生成

## 环境准备

### 方式一：Docker（推荐）

镜像基于 `ubuntu:20.04`，安装了 `gcc-multilib`、`gdb`、`pwntools`、`ROPgadget`，32 位程序可以原生运行。

```bash
bash scripts/docker_run.sh                       # 构建镜像并进入容器
bash scripts/build_all.sh                        # 容器内编译全部靶程序
bash scripts/run_all.sh                          # 容器内跑通全部利用
```

> 注意：在 Apple Silicon Mac 上需要 **x86_64 架构** 的虚拟机/容器，因为 32 位 i386 程序无法在 arm64 下直接执行。本项目在 colima + Docker(`--platform linux/amd64`) + qemu-user 下验证通过；此时 gdb 的 ptrace 不可用，调试以 `objdump`、核心转储与 `--check` 输出为准。

### 方式二：本地 Linux

```bash
sudo apt install gcc-multilib gdb python3-pip
pip3 install pwntools ropgadget
bash scripts/build_all.sh
bash scripts/run_all.sh
```

## 手动复现单个案例

以 ret2text 为例：

```bash
cd challenges/ret2text
gcc -m32 -O0 -fno-stack-protector -fno-builtin -no-pie -o ret2text src.c
python3 exp.py            # 拿到交互式 shell
python3 exp.py --check    # 自动验证，输出 PASS/FAIL
```

其它案例把目录名换掉即可；`ret2libc3` 需要先把容器内的 32 位 `libc.so.6` 复制到该目录（`build_all.sh` 会自动完成）。

## 编译参数说明

| 参数 | 作用 |
|---|---|
| `-m32` | 生成 32 位程序，栈传参、指针 4 字节，便于构造 ROP 链 |
| `-fno-stack-protector` | 关闭 Canary，允许直接覆盖返回地址 |
| `-no-pie` | 关闭地址随机化，代码段基址固定，便于引用符号 |
| `-fno-builtin` | 避免编译器把 `gets` 等函数优化掉 |
| `-static` | （仅 ret2syscall）把 libc 静态链入，保证 gadget 齐全 |
| `-z execstack` | （仅 ret2shellcode）把栈标记为可执行 |

## 目录结构

```
.
├── challenges/
│   ├── Makefile              # 六个靶程序的统一编译规则
│   ├── ret2text/
│   │   ├── src.c
│   │   └── exp.py
│   ├── ret2shellcode/
│   ├── ret2syscall/
│   ├── ret2libc1/
│   ├── ret2libc2/
│   └── ret2libc3/
├── docker/
│   └── Dockerfile
├── docs/
│   └── report.md             # 实验报告正文
└── scripts/
    ├── build_all.sh          # 编译全部靶程序
    ├── run_all.sh            # 自动验证全部利用
    └── docker_run.sh         # 构建并进入实验容器
```

## 代码仓库

<https://github.com/zzb040506/EX2A-ROP>

## 免责声明

所有靶程序均为课程实验自行编写，仅用于在本地隔离环境中学习二进制漏洞利用原理。请勿将相关技术用于未授权的系统。
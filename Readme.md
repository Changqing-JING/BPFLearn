## Setup BPF development evnvironment

```shell
sudo apt install flex bison libelf-dev binutils-dev libssl-dev libcap-dev c bpftrace libbpf-dev
sudo ln -s /usr/include/asm-generic /usr/include/asm
```

### Build BPF hello world

```shell
mkdir build
cd build
cmake ..
make
sudo ./hello
```

###

Use BPF to watch TCP

```shell
./build/socket_demo/TcpServer
```

In a new terminal run

```shell
sudo bpftrace socket_demo/tcp.bt
```

In a thrid terminal

```shell
./build/socket_demo/TcpClient
```

####

Watch TCP connect

```
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_connect{printf("connect\n");}'
```

Watch Accept

```
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_accept{printf("accept\n");} tracepoint:syscalls:sys_enter_accept4{printf("accept4\n");}'
```

## BPF Toolings

```shell
#how active bpf programs
sudo bpftool prog show
#dump bpf bytecode
sudo bpftool prog dump xlated id 40 opcode
#show number of system calls of each process in a time period
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter{@[comm]=count();}'
# search bpf hooks
sudo bpftrace -l "*accept*"
# Test if current platform support BPF
sudo bpftrace -e 'BEGIN{printf("begin\n");} END{printf("end\n");}'
```

# For information

## Build BPF inside kernel folder on ubuntu 22.04

Beside using Ubuntu's bpf library, bpf can also be built from kernel source folder if libbpf-dev is not provided on some platform

```shell
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
linux-stable
checkout v5.15.25

make defconfig -j 8
make modules_prepare -j 8
make headers_install -j 8
make M=samples/bpf
make VMLINUX_BTF=/sys/kernel/btf/vmlinux -C samples/bpf -j 8
./scripts/clang-tools/gen_compile_commands.py
```

## compile bpf with clang command

```shell
clang -target bpf -c hello_kern.c -o hello_kern.o

#or
clang -emit-llvm -S hello_kern.c
llc hello_kern.ll -march=bpf -filetype=obj -o hello_kern.o

```

## Read sections of elf files

```shell
readelf -S hello_kern.o
llvm-objdump -d hello_kern.o

#supported backend by llvm
llc --version

#list cpu info
lscpu
```

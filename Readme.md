## Setup BPF development evnvironment
```shell
sudo apt install flex bison libelf-dev binutils-dev libssl-dev libcap-dev gcc-multilib bpftrace
```
### Build BPF hello world
```shell
mkdir build
cd build
cmake ..
make
sudo ./hello
```
## BPF Toolings
```shell
#how active bpf programs
sudo bpftool prog show 
#dump bpf bytecode
sudo bpftool prog dump xlated id 40 opcode
#show number of system calls of each process in a time period
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter{@[comm]=count();}'

```
### Build BPF inside kernel folder on ubuntu 22.04
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
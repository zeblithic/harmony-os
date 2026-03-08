# Minimal x86_64 Linux binary for Linuxulator MVP testing.
# Calls write(1, "Hello\n", 6) then exit_group(0).
#
# Build: x86_64-linux-gnu-as -o hello.o hello.S && x86_64-linux-gnu-ld -o hello.elf -nostdlib --static hello.o
# Or on Linux: as -o hello.o hello.S && ld -o hello.elf -nostdlib --static hello.o

.globl _start
_start:
    # write(1, msg, 6)
    mov $1, %rax            # syscall: write
    mov $1, %rdi            # fd: stdout
    lea msg(%rip), %rsi     # buf: address of message
    mov $6, %rdx            # count: 6 bytes
    syscall

    # exit_group(0)
    mov $231, %rax          # syscall: exit_group
    xor %rdi, %rdi          # code: 0
    syscall

msg:
    .ascii "Hello\n"

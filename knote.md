# d3ctf knote

## IDA
```c
def ioctl(fd, cmd, arg):
	mychunk = arg
	if cmd == 0x2333:
		get()
	elif cmd == 0x1337:
		add()
	elif cmd == 0x8888:
		edit()
	elif cmd == 0x6666:
		dele()

def add()：
		size = mychunk.size
		read_lock()
		idx = search_empty_buf()
		write_lock()
		mybuf[idx].ptr = kmalloc(size)
		myuf[idx].size = size
		unlock()
def get():
	idx = mychunk.idx
	copy_user_generic_unrolled(mychunk.ptr, mybuf[idx].ptr, mybuf[idx].size)
def edit():
	idx = mychunk.idx
	copy_user_generic_unrolled(mybuf[idx].ptr, mychunk.ptr, mybuf[idx].size)
def dele():
	idx = mychunk.idx
	ptr = &mybuf[idx]
	write_lock()
	free(ptr)
	ptr->ptr = 0
	ptr->size = 0
	unlock()
```

存在读写锁，然而在get和edit操作时并没有加锁

## 利用

1. 利用userfaultfd泄露地址
2. 利用userfaultfd修改`chunk→freelist`指针

```c
1. 信息泄露
get(0) -> userfaultfd -> dele(0) -> open("/dev/ptmx") -> return get(0)
2. 修改modprobe_path
edit(0) -> userfaultfd -> dele(0) -> freelist=modeprobe_path -> add(0x20)
=> edit(1, "/tmp/shell.sh")
execve(badfile)
```

在最后执行badfile时可能会报错，可以先释放一些0x20的chunk，再执行

### ref

[github](https://github.com/Ex-Origin/ctf-writeups/tree/master/d3ctf2019/pwn/knote)

[writeup](https://blog.csdn.net/seaaseesa/article/details/104650794)

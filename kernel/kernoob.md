# kernoob

## IDA

```python
"""
Arg: {idx, ptr, size}
"""
def oob_ioctl(fd, cmd, arg):
	if cmd == 0x30001:
		del_note(arg)
	elif cmd == 0x30002:
		edit_note(arg)
	elif cmd == 0x30003:
		show_note(arg)
	elif cmd == 0x30000:
		add_note(arg)
	
def add_note(arg):
	assert(arg.size >= 0x20 and arg.size <= 0x70)
	pool[arg.idx] = kmalloc(arg.size)
def edit_note(arg):
	copy_from_user(pool[arg.idx].ptr, arg.ptr, arg.size)
def show_note(arg):
	copy_to_user(arg.ptr, pool[arg.idx].ptr, arg.size)
def del_note(arg):
	kfree(pool[arg.idx].ptr) # UAF, since not clear ptr and size of pool[arg.idx]
	
```

存在明显的UAF漏洞，但是note的大小有限制(<=0x60)。

## 利用

### 1. UAF
通过seq_operations来填充note，再通过edit_note修改seq_operations的指针，最终控制程序执行流。

### 2. modprobe_path
```
1. 设UAF的SLUB为slub1，修改slub1->freelist = slub1^random^target1,
	target1 = (mod_base ^ random)>>32属于用户空间
2. alloc(0x60)申请slub1为notei，alloc(0x60)申请到用户空间为notej，因此notej的地址为用户空间
3. mmap(target1)并且修改*target1 = target1^random^target2,
	target2 = notej-4，alloc(0x60)申请notek
4. alloc(0x60)时，target3=(target1<<32)^(notej-4)^random肯定也在用户空间，
	mmap(target3)即可，这个空间也必须分配，否则另外一个core分配0x60时，由于没有mmap映射，因此
	也会crash
5. 通过notek修改notej->ptr = modprobe_path，通过notej设置modprobe_path为fake_script
6. 执行错误格式的程序，执行fake_script
```

```
modprobe_tree, poweroff_cmd,Hijack Prctl
注意给copy.sh和kirin加可执行权限
```

除了0x60SLUB块的0x28处包含堆块指针的方法外，[url](https://n0nop.com/2021/03/29/kernel-pwn-kernoob-%E4%B8%8D%E4%BB%85%E4%BB%85%E6%98%AFdouble-fetch/#%E4%BF%AE%E6%94%B9%E5%86%85%E6%A0%B8%E4%B8%AD%E7%9A%84%E5%85%A8%E5%B1%80%E5%8F%98%E9%87%8F)提供了另外一种泄露random地址的方法。

### ref

[https://kirin-say.top/2020/03/10/Kernoob-kmalloc-without-SMAP](https://kirin-say.top/2020/03/10/Kernoob-kmalloc-without-SMAP)

[https://matshao.com/2020/03/15/XCTF新春战疫-kernoob/](https://matshao.com/2020/03/15/XCTF%E6%96%B0%E6%98%A5%E6%88%98%E7%96%AB-kernoob/)

[https://n0nop.com/2021/03/29/kernel-pwn-kernoob-不仅仅是double-fetch/](https://n0nop.com/2021/03/29/kernel-pwn-kernoob-%E4%B8%8D%E4%BB%85%E4%BB%85%E6%98%AFdouble-fetch/)


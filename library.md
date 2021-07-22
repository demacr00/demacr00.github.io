# 3kctf2021 library
## IDA

实现了book的增删查改

```c
struct book
{
  char name[0x300];
  size_t idx;
  book *next;
  book *prev;
};
.bss: root # book*
def add(idx): #0x3000
	newbook = kmem_cache_alloc()
	last, ptr = get_empty_ptr(root)
	last->next = newbook
	newbook->prev = last
	newbook->next = 0
	++counter
def dele(idx): #0x3001
	book = find_book_by_id(root)
	delete(book)
	update_list() #没有判断是否删除最后一本书，存在null dereference
	--counter
def removeall(): #0x3002
	removeall() #与其余操作不共用一把锁，存在竞争和UAF
	counter = 1
def edit(idx, ptr): #0x3003
	book = find_book_by_idx(idx)
	copy_from_user(book, ptr)
def show(idx, ptr): #0x3004
	book = find_book_by_idx(idx)
	copy_to_user(book, ptr)
```

思路：由于安全机制全开，因此首先泄漏，然后在利用。

1. tty_struct

```c
# LEAK
1. userfaultfd+UAF
add(0)
show(0, fault_page) => removeall() => spray tty_struct
2. uninit memory
spray tty_struct and delete them
add(0)
show(0)
#前0x20的内容无法泄漏

# EXPLOIT
1. userfaultfd+UAF
add(0)
edit(0, fault_page) => removeall() => spray tty_struct
2. userfaultfd+modprobe_path
add(0)
edit(0, fault_page) => removeall() => modify next freepointer
发现这道题中的kmem_cache[10]的freelist在0x200，因此需要修改偏移0x200的位置为modprobe_path
问题：发现每次kmem_cache_alloc会清空申请到的cache，因此这种方法不可取。

根本原因：
newbook = (book *)kmem_cache_alloc(kmalloc_caches[10], 0xDC0LL);// will memset
#define ___GFP_ZERO     0x100u
kmem_cache_alloc => slab_alloc => slab_alloc_node:
if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
        memset(object, 0, s->object_size);
```

```c
freelist = 0x200 in kmem_cache[10]
探索所有大小的freelist
```

[https://meowmeowxw.gitlab.io/ctf/3k-2021-klibrary/](https://meowmeowxw.gitlab.io/ctf/3k-2021-klibrary/)

## 问题与解决方案

1. freelist的位置判断
2. kmem_cache_alloc的flags包含___GFP_ZERO时会清空申请到的内容
3. 伪造的freelist应为有物理页面的映射，否则可能会pagefualt崩溃，例如如果将freelist设为book0-0x100则会崩溃
4. book的页面重叠的时候，注意恢复book的id
5. 用tty_struct来retrive释放的book，会存在不稳定的现象，但是如果spray tty_struct，则会导致获得的堆地址不精确。本来想通过bind_on_cores来绑定核，但是会失败。后面发现通过xxd打印则会变得非常稳定。。。
6. 信号量会失败；bind_on_cores会失败。猜测可能与内核版本相关。

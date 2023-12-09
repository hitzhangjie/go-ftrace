# offsets.py

## 如何使用这个脚本

这个脚本使用Linux工具'pahole'来检查带有DWARF调试信息的ELF二进制文件，并提取指定对象的偏移量。

例如，提取`runtime.g->goid`和`runtime.g->stack->hi`的偏移量：

```bash
$ ./offsets.py --bin ftrace --expr runtime.g->goid
+152(_)

$ ./offsets.py --bin ftrace --expr runtime.g->stack
struct runtime.stack {
        uintptr                    lo;                   /*     0     8 */
        uintptr                    hi;                   /*     8     8 */

        /* size: 16, cachelines: 1, members: 2 */
        /* last cacheline: 16 bytes */
};
+0(_)

$ ./offsets.py --bin ftrace --expr runtime.g->stack->hi
+8(_)
```

## 这个脚本是如何工作的

首先，这个脚本将使用'pahole'工具来检查带有DWARF调试信息的ELF二进制文件中指定对象的填充(paddings)和空洞(holes)。

例如，当我们运行'pahole -C runtime.g ftrace'时，它的输出如下：

```bash
$ pahole -C runtime.g ftrace
struct runtime.g {
        runtime.stack              stack;                /*     0    16 */
        uintptr                    stackguard0;          /*    16     8 */
        uintptr                    stackguard1;          /*    24     8 */
        runtime._panic *           _panic;               /*    32     8 */
        runtime._defer *           _defer;               /*    40     8 */
        runtime.m *                m;                    /*    48     8 */
        runtime.gobuf              sched;                /*    56    56 */
        /* --- cacheline 1 boundary (64 bytes) was 48 bytes ago --- */
        uintptr                    syscallsp;            /*   112     8 */
        uintptr                    syscallpc;            /*   120     8 */
        /* --- cacheline 2 boundary (128 bytes) --- */
        uintptr                    stktopsp;             /*   128     8 */
        void *                     param;                /*   136     8 */
        runtime/internal/atomic.Uint32 atomicstatus;     /*   144     4 */
        uint32                     stackLock;            /*   148     4 */
        uint64                     goid;                 /*   152     8 */
        runtime.guintptr           schedlink;            /*   160     8 */
        int64                      waitsince;            /*   168     8 */
        runtime.waitReason         waitreason;           /*   176     1 */
        bool                       preempt;              /*   177     1 */
        bool                       preemptStop;          /*   178     1 */
        bool                       preemptShrink;        /*   179     1 */
        bool                       asyncSafePoint;       /*   180     1 */
        bool                       paniconfault;         /*   181     1 */
        bool                       gcscandone;           /*   182     1 */
        bool                       throwsplit;           /*   183     1 */
        bool                       activeStackChans;     /*   184     1 */
        runtime/internal/atomic.Bool parkingOnChan;      /*   185     1 */
        int8                       raceignore;           /*   186     1 */
        bool                       tracking;             /*   187     1 */
        uint8                      trackingSeq;          /*   188     1 */

        /* XXX 3 bytes hole, try to pack */

        /* --- cacheline 3 boundary (192 bytes) --- */
        int64                      trackingStamp;        /*   192     8 */
        int64                      runnableTime;         /*   200     8 */
        runtime.muintptr           lockedm;              /*   208     8 */
        uint32                     sig;                  /*   216     4 */

        /* XXX 4 bytes hole, try to pack */

        struct []uint8             writebuf;             /*   224    24 */
        uintptr                    sigcode0;             /*   248     8 */
        /* --- cacheline 4 boundary (256 bytes) --- */
        uintptr                    sigcode1;             /*   256     8 */
        uintptr                    sigpc;                /*   264     8 */
        uint64                     parentGoid;           /*   272     8 */
        uintptr                    gopc;                 /*   280     8 */
        struct []runtime.ancestorInfo * ancestors;       /*   288     8 */
        uintptr                    startpc;              /*   296     8 */
        uintptr                    racectx;              /*   304     8 */
        runtime.sudog *            waiting;              /*   312     8 */
        /* --- cacheline 5 boundary (320 bytes) --- */
        struct []uintptr           cgoCtxt;              /*   320    24 */
        void *                     labels;               /*   344     8 */
        runtime.timer *            timer;                /*   352     8 */
        runtime/internal/atomic.Uint32 selectDone;       /*   360     4 */
        runtime.goroutineProfileStateHolder goroutineProfiled; /*   364     4 */
        runtime.gTraceState        trace;                /*   368    32 */
        /* --- cacheline 6 boundary (384 bytes) was 16 bytes ago --- */
        int64                      gcAssistBytes;        /*   400     8 */

        /* size: 408, cachelines: 7, members: 50 */
        /* sum members: 401, holes: 2, sum holes: 7 */
        /* last cacheline: 24 bytes */
};
```

然后，这个脚本将使用正则表达式来解析输出并提取指定对象的成员偏移量。

对于 runtime.g，它将提取所有成员的偏移量，例如：
```
- type=runtime.stack, name=stack, offset=6
- type=uintptr, name=stackguard0, offset=16
- type=uintptr, name=stackguard1, offset=24
- ...
```

如果我们指定 `./offsets.py --expr runtime.g->stack`，它将在 runtime.g 中找到成员 'stack'，并打印其成员的偏移量。

如果我们指定 `./offsets.py --expr runtime.g->stack->hi`，它将首先在 runtime.g 中找到成员 'stack'，然后在 runtime.stack 中找到成员 'hi'，并打印其偏移量。

简而言之，借助 DWARF、pahole 和 RegExp，offsets.py的工作原理大致就是这样的。

## 为什么我们需要这个脚本

当我们使用 `go-ftrace` 跟踪用户定义的函数和运行时函数时，我们可能想要获取或设置参数的成员，因此我们需要知道偏移量。

这个 **offsets.py** 将帮助我们获取偏移量，以便使用eBPF程序去跟踪函数及其参数时来设定参数的有效地址。

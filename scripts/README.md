# offsets.py

## How to usage this script

this script uses Linux tool 'pahole' to inspect ELF binary with DWARF debugging info and extract offsets of specified objects.

for example, extract the offsets of `runtime.g->goid` and `runtime.g->stack->hi`:

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

## How does this script work

first, this script will use 'pahole' to inspect the padding and holes of specified object in the ELF bniary with the help of DWARF.

for example, when we run 'pahole -C runtime.g ftrace', it outputs:

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

then, this script will use RegExp to parse the output and extract the offsets of members of the specified object.

for the runtime.g, it will extract all the member offsets, like:
```
- type=runtime.stack, name=stack, offset=6
- type=uintptr, name=stackguard0, offset=16
- type=uintptr, name=stackguard1, offset=24
- ...
```

if we specify `./offsets.py --expr runtime.g->stack`, it will find the member 'stack' in runtime.g, and prints its members' offsets.

if we specify `./offsets.py --expr runtime.g->stack->hi`, it will first find the member 'stack' in runtime.g, then find the member 'hi' in runtime.stack, and prints its offset.

at a nutshell, it works like this with the help of DWARF, pahole and RegExp.

## Why we need this script

when we `go-ftrace` to trace the user-defined functions and runtime functions, we may want to get or set the members of arguments, then we need to know the offsets.

well, this offsets.py will help us to get the offsets, so we can write eBPF programme more easily.

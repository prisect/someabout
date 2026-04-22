# libtestosterone.so

A dynamic linker preload library that injects “testosterone-driven” behavior into any process.

The theme is stupid; the implementation is careful: it uses `dlsym(RTLD_NEXT, ...)` hooks, avoids recursion pitfalls, and uses inline assembly where requested.

## Build

```bash
cd libtestosterone
make
```

This produces `libtestosterone.so`.

## Run (one-shot)

```bash
TESTOSTERONE_LEVEL=85 LD_PRELOAD=./libtestosterone.so ls -la
```

## Run (aggressive shell)

```bash
export TESTOSTERONE_LEVEL=90
LD_PRELOAD=./libtestosterone.so bash
```

Optional: disable ANSI colors in logs:

```bash
TESTOSTERONE_COLOR=0 TESTOSTERONE_LEVEL=85 LD_PRELOAD=./libtestosterone.so ls -la
```

## Behaviors

- **`malloc`**: on allocation failure, prints a macho log, lowers the priority (increases `nice` by +5) of other processes owned by the same user via raw `syscall` (`SYS_getpriority`/`SYS_setpriority`), then retries `malloc` once. It best-effort restores the original priorities after the retry.
- **`sched_yield`**: if level > 70, spins for `(level - 50) * 2000` iterations using `__asm__ volatile("rep nop")`, then yields. Otherwise it yields normally.
- **`open` + `flock` (alpha file lock)**: `flock(LOCK_EX)` consults a SysV shared-memory table keyed by inode. If the caller’s level is higher than the recorded owner’s level, it attempts an immediate “takeover” by atomically swapping ownership using a `lock cmpxchgq` CAS on a 64-bit `(inode_key<<16)|pid16` tag. If lower, it sleeps `usleep((100 - level)*1000)` before retrying. It still calls the real kernel `flock` (with `LOCK_NB` retries, then blocking fallback) to preserve normal semantics when possible.
- **`send` / `recv`**: on the first call per socket fd, uses `getsockopt` + `setsockopt` to increase `SO_SNDBUF` and `SO_RCVBUF` by `(level * 1024)` bytes and logs `[T::XX] Socket buffers boosted for dominance.`

## Notes / caveats

- The “alpha lock” protocol is cooperative across processes using this preload; it also attempts to take the real kernel `flock`, but a non-preloaded process holding a lock can still block you (even if you’re very alpha).
- The inode key stored in shared memory is truncated to 48 bits to fit the required `(inode<<16)|pid` packing; collisions are possible but extremely funny.


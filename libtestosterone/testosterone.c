#define _GNU_SOURCE
/*
 * libtestosterone.so - a humorous but robust LD_PRELOAD “dominance” layer.
 *
 * Intercepts:
 *   - malloc
 *   - sched_yield
 *   - open + flock (alpha file lock)
 *   - send + recv
 *
 * TESTOSTERONE_LEVEL in [0..100] controls behavior (default 50).
 *
 * This is intended for modern x86-64 Linux with glibc.
 */

#if !defined(__x86_64__)
#error "libtestosterone.so currently targets x86-64 (for the inline asm requirements)."
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------- raw syscalls (inline asm) -------------------------
 * For the "priority boost" path, we prefer direct syscall instruction usage
 * for maximum machismo and to reduce libc dependencies inside malloc failure.
 */

static inline long raw_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  long ret;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

static inline long raw_syscall3(long n, long a1, long a2, long a3) {
  return raw_syscall6(n, a1, a2, a3, 0, 0, 0);
}

static inline long raw_syscall2(long n, long a1, long a2) {
  return raw_syscall6(n, a1, a2, 0, 0, 0, 0);
}

static inline long raw_syscall1(long n, long a1) {
  return raw_syscall6(n, a1, 0, 0, 0, 0, 0);
}

static inline long raw_syscall0(long n) {
  return raw_syscall6(n, 0, 0, 0, 0, 0, 0);
}

static inline ssize_t raw_write(int fd, const void *buf, size_t len) {
  return (ssize_t)raw_syscall3(SYS_write, fd, (long)buf, (long)len);
}

/* ------------------------------ logging ----------------------------------- */

static int g_use_color = 1;

static void tlogf(int level, const char *fmt, ...) {
  char buf[768];
  int n = 0;

  if (g_use_color) {
    n += snprintf(buf + n, sizeof(buf) - (size_t)n, "\033[1;35m[T::%02d]\033[0m ", level);
  } else {
    n += snprintf(buf + n, sizeof(buf) - (size_t)n, "[T::%02d] ", level);
  }

  va_list ap;
  va_start(ap, fmt);
  n += vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
  va_end(ap);

  if (n < (int)sizeof(buf) - 2) {
    buf[n++] = '\n';
    buf[n] = '\0';
  } else {
    buf[sizeof(buf) - 2] = '\n';
    buf[sizeof(buf) - 1] = '\0';
    n = (int)sizeof(buf) - 1;
  }

  (void)raw_write(2, buf, (size_t)n);
}

/* -------------------------- testosterone level ---------------------------- */

static _Atomic int g_level_cached = -1;

static int clamp_int(int v, int lo, int hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

static int testosterone_level(void) {
  int cached = __atomic_load_n(&g_level_cached, __ATOMIC_RELAXED);
  if (cached >= 0) return cached;

  int level = 50;
  const char *s = getenv("TESTOSTERONE_LEVEL");
  if (s && *s) {
    int sign = 1;
    if (*s == '-') {
      sign = -1;
      s++;
    }
    long v = 0;
    while (*s >= '0' && *s <= '9') {
      v = v * 10 + (*s - '0');
      if (v > 1000) break;
      s++;
    }
    level = (int)(v * sign);
  }
  level = clamp_int(level, 0, 100);
  __atomic_store_n(&g_level_cached, level, __ATOMIC_RELAXED);
  return level;
}

/* ---------------------- bootstrap allocator (reentrancy) ------------------ */

/*
 * dlsym()/loader paths can call malloc very early. When our malloc is invoked
 * before we've resolved the real malloc, we use a tiny bump allocator backed
 * by mmap. This is not a general-purpose allocator; it's only for bootstrap.
 */

static _Atomic int g_boot_ready = 0;
static uint8_t *g_boot_base = NULL;
static size_t g_boot_off = 0;

static void *bootstrap_alloc(size_t size) {
  const size_t arena_size = 64 * 1024;
  size = (size + 15u) & ~15u;

  if (!__atomic_load_n(&g_boot_ready, __ATOMIC_ACQUIRE)) {
    void *p = (void *)raw_syscall6(SYS_mmap, 0, arena_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((intptr_t)p < 0) return NULL;
    g_boot_base = (uint8_t *)p;
    g_boot_off = 0;
    __atomic_store_n(&g_boot_ready, 1, __ATOMIC_RELEASE);
  }

  if (!g_boot_base) return NULL;
  if (g_boot_off + size > arena_size) return NULL;
  void *out = g_boot_base + g_boot_off;
  g_boot_off += size;
  return out;
}

/* ---------------------------- symbol resolution --------------------------- */

static void *(*real_malloc)(size_t) = NULL;
static int (*real_sched_yield)(void) = NULL;
static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_flock)(int, int) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;

static __thread int g_in_hook = 0;
static _Atomic int g_resolving = 0;

static void resolve_symbols(void) {
  if (real_malloc && real_sched_yield && real_open && real_flock && real_send && real_recv) return;
  if (__atomic_exchange_n(&g_resolving, 1, __ATOMIC_ACQ_REL)) return;

  g_in_hook++;
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_sched_yield = dlsym(RTLD_NEXT, "sched_yield");
  real_open = dlsym(RTLD_NEXT, "open");
  real_flock = dlsym(RTLD_NEXT, "flock");
  real_send = dlsym(RTLD_NEXT, "send");
  real_recv = dlsym(RTLD_NEXT, "recv");
  g_in_hook--;

  __atomic_store_n(&g_resolving, 0, __ATOMIC_RELEASE);
}

/* ------------------------ sched_yield aggression -------------------------- */

int sched_yield(void) {
  resolve_symbols();
  if (!real_sched_yield) return 0;

  int level = testosterone_level();
  if (level > 70 && !g_in_hook) {
    uint64_t iters = (uint64_t)(level - 50) * 2000u;
    tlogf(level, "sched_yield – spinning before yield (aggressive mode), iters=%llu",
          (unsigned long long)iters);

    /* Inline asm spin loop using x86 PAUSE (rep nop). */
    for (uint64_t i = 0; i < iters; i++) {
      __asm__ volatile("rep nop" ::: "memory");
    }
  }

  return real_sched_yield();
}

/* ----------------------- "evict rivals" nice tweak ------------------------ */

/*
 * On malloc failure, we:
 *   - find all processes owned by our uid (excluding ourselves)
 *   - increase their nice value by +5 (lower priority)
 *   - retry malloc once
 *   - best-effort restore nice values after retry
 *
 * Implementation avoids libc malloc by using raw syscalls and fixed buffers.
 */

struct prio_save {
  int pid;
  int old_prio;
};

static int parse_int(const char *s) {
  int v = 0;
  while (*s >= '0' && *s <= '9') {
    v = v * 10 + (*s - '0');
    s++;
  }
  return v;
}

static bool is_digit_str(const char *s) {
  if (!*s) return false;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return false;
  }
  return true;
}

struct linux_dirent64 {
  uint64_t d_ino;
  int64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

static uid_t read_uid_for_pid(int dirfd, int pid) {
  char path[64];
  int len = snprintf(path, sizeof(path), "%d/status", pid);
  if (len <= 0 || (size_t)len >= sizeof(path)) return (uid_t)-1;

  int fd = (int)raw_syscall6(SYS_openat, dirfd, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
  if (fd < 0) return (uid_t)-1;

  char buf[2048];
  ssize_t r = (ssize_t)raw_syscall3(SYS_read, fd, (long)buf, (long)(sizeof(buf) - 1));
  (void)raw_syscall1(SYS_close, fd);
  if (r <= 0) return (uid_t)-1;
  buf[r] = '\0';

  /* Parse the "Uid:" line: Uid:\t<real>\t<effective>\t... */
  const char *p = strstr(buf, "\nUid:");
  if (!p) {
    /* Might be at file start. */
    if (strncmp(buf, "Uid:", 4) == 0) p = buf;
    else return (uid_t)-1;
  } else {
    p++; /* skip '\n' */
  }
  p += 4;
  while (*p == ' ' || *p == '\t') p++;
  return (uid_t)parse_int(p);
}

static void evict_rivals_once(void) {
  uid_t me_uid = getuid();
  pid_t me_pid = getpid();

  int procfd = (int)raw_syscall6(SYS_openat, AT_FDCWD, (long)"/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                                0, 0, 0);
  if (procfd < 0) return;

  struct prio_save saved[256];
  int saved_n = 0;

  char dents[8192];
  for (;;) {
    long nread = raw_syscall3(SYS_getdents64, procfd, (long)dents, (long)sizeof(dents));
    if (nread <= 0) break;

    for (long bpos = 0; bpos < nread;) {
      struct linux_dirent64 *d = (struct linux_dirent64 *)(dents + bpos);
      bpos += d->d_reclen;
      if (!is_digit_str(d->d_name)) continue;

      int pid = parse_int(d->d_name);
      if (pid <= 0 || pid == (int)me_pid) continue;

      uid_t uid = read_uid_for_pid(procfd, pid);
      if (uid == (uid_t)-1 || uid != me_uid) continue;

      /* getpriority/setpriority syscalls (machismo path) */
      long oldp = raw_syscall2(SYS_getpriority, PRIO_PROCESS, pid);
      if (oldp < 0) continue;

      int newp = (int)oldp + 5;
      if (newp > 19) newp = 19;
      if (newp == (int)oldp) continue;

      (void)raw_syscall3(SYS_setpriority, PRIO_PROCESS, pid, newp);

      if (saved_n < (int)(sizeof(saved) / sizeof(saved[0]))) {
        saved[saved_n++] = (struct prio_save){.pid = pid, .old_prio = (int)oldp};
      }
    }
  }

  (void)raw_syscall1(SYS_close, procfd);

  /* Best-effort restore priorities. */
  for (int i = 0; i < saved_n; i++) {
    (void)raw_syscall3(SYS_setpriority, PRIO_PROCESS, saved[i].pid, saved[i].old_prio);
  }
}

void *malloc(size_t size) {
  if (g_in_hook) return bootstrap_alloc(size);
  resolve_symbols();

  if (!real_malloc) return bootstrap_alloc(size);

  void *p = real_malloc(size);
  if (p) return p;

  int level = testosterone_level();
  tlogf(level, "malloc failed – boosting priority, evicting rivals.");

  int saved_errno = errno;
  g_in_hook++;
  evict_rivals_once();
  g_in_hook--;
  errno = saved_errno;

  /* Retry once. */
  return real_malloc(size);
}

/* -------------------------- alpha lock (SysV shm) -------------------------- */

/*
 * Shared memory table keyed by a truncated inode key.
 *
 * Atomic ownership is tracked by owner_tag:
 *   owner_tag = (inode_key << 16) | pid16
 *
 * Requirements ask for a 64-bit `lock cmpxchg` CAS on that value.
 *
 * Note: inode_key is truncated to 48 bits to fit (inode_key<<16) in 64 bits.
 * This is fine for this comedic "alpha" protocol; collisions are possible.
 */

#define ALPHA_MAGIC 0x54414C50u /* "TALP" */
#define ALPHA_SLOTS 2048u       /* must be power of two */

struct alpha_slot {
  _Atomic uint64_t owner_tag;  /* (inode_key<<16)|pid16 */
  _Atomic uint32_t owner_meta; /* (level<<16)|pid16 */
};

struct alpha_table {
  _Atomic uint32_t magic;
  uint32_t slots;
  struct alpha_slot slot[ALPHA_SLOTS];
};

static struct alpha_table *g_alpha = NULL;

static inline uint64_t inode_key48(uint64_t inode) {
  return inode & 0x0000FFFFFFFFFFFFULL;
}

/* Single atomic CAS using lock cmpxchgq on a uint64_t. */
static inline bool cas_u64_lock_cmpxchg(_Atomic uint64_t *ptr, uint64_t expected, uint64_t desired) {
  unsigned char ok;
  __asm__ volatile("lock cmpxchgq %3, %1; sete %0"
                   : "=q"(ok), "+m"(*ptr), "+a"(expected)
                   : "r"(desired)
                   : "cc", "memory");
  return ok != 0;
}

static void alpha_init(void) {
  if (g_alpha) return;

  /* Fixed key so all preloaded processes meet in the same alpha arena. */
  key_t key = (key_t)0x54455354; /* "TEST" */
  long shmid = raw_syscall3(SYS_shmget, (long)key, (long)sizeof(struct alpha_table), IPC_CREAT | 0600);
  if (shmid < 0) return;

  void *addr = (void *)raw_syscall3(SYS_shmat, shmid, 0, 0);
  if ((intptr_t)addr == -1) return;

  g_alpha = (struct alpha_table *)addr;

  uint32_t expect0 = 0;
  if (__atomic_compare_exchange_n(&g_alpha->magic, &expect0, ALPHA_MAGIC, false, __ATOMIC_ACQ_REL,
                                  __ATOMIC_ACQUIRE)) {
    g_alpha->slots = ALPHA_SLOTS;
    for (uint32_t i = 0; i < ALPHA_SLOTS; i++) {
      __atomic_store_n(&g_alpha->slot[i].owner_tag, 0, __ATOMIC_RELAXED);
      __atomic_store_n(&g_alpha->slot[i].owner_meta, 0, __ATOMIC_RELAXED);
    }
  } else {
    /* If already initialized by another process, respect it. */
    if (__atomic_load_n(&g_alpha->magic, __ATOMIC_ACQUIRE) != ALPHA_MAGIC) {
      g_alpha = NULL;
    }
  }
}

static struct alpha_slot *alpha_find_slot(uint64_t ikey) {
  if (!g_alpha) return NULL;
  uint64_t h = ikey * 11400714819323198485ULL;
  uint32_t idx = (uint32_t)h & (ALPHA_SLOTS - 1u);
  for (uint32_t probe = 0; probe < ALPHA_SLOTS; probe++) {
    struct alpha_slot *s = &g_alpha->slot[idx];
    uint64_t tag = __atomic_load_n(&s->owner_tag, __ATOMIC_ACQUIRE);
    uint64_t tag_ikey = tag >> 16;
    if (tag == 0 || tag_ikey == ikey) return s;
    idx = (idx + 1u) & (ALPHA_SLOTS - 1u);
  }
  return NULL;
}

static int alpha_acquire_owner(int fd, uint64_t inode, int caller_level) {
  alpha_init();
  if (!g_alpha) return 0; /* no alpha arena; behave normally */

  uint64_t ikey = inode_key48(inode);
  struct alpha_slot *slot = alpha_find_slot(ikey);
  if (!slot) return 0;

  uint16_t pid16 = (uint16_t)(getpid() & 0xFFFF);
  uint64_t mytag = (ikey << 16) | (uint64_t)pid16;
  uint32_t mymeta = ((uint32_t)caller_level << 16) | (uint32_t)pid16;

  int slept = 0;
  for (int attempt = 0; attempt < 200; attempt++) {
    uint64_t oldtag = __atomic_load_n(&slot->owner_tag, __ATOMIC_ACQUIRE);
    uint64_t old_ikey = oldtag >> 16;
    if (oldtag != 0 && old_ikey != ikey) {
      slot = alpha_find_slot(ikey);
      if (!slot) return 0;
      continue;
    }

    uint32_t oldmeta = __atomic_load_n(&slot->owner_meta, __ATOMIC_ACQUIRE);
    int owner_level = (int)(oldmeta >> 16);
    uint16_t owner_pid16 = (uint16_t)(oldmeta & 0xFFFF);

    if (oldtag == mytag || owner_pid16 == pid16) {
      /* Already the alpha (or re-entrant locking). */
      __atomic_store_n(&slot->owner_meta, mymeta, __ATOMIC_RELEASE);
      return 1;
    }

    if (oldtag == 0) {
      if (cas_u64_lock_cmpxchg(&slot->owner_tag, 0, mytag)) {
        __atomic_store_n(&slot->owner_meta, mymeta, __ATOMIC_RELEASE);
        if (caller_level > 70) tlogf(caller_level, "alpha lock – claimed fresh territory (inode=%llu)",
                                     (unsigned long long)inode);
        return 1;
      }
      continue;
    }

    if (caller_level > owner_level) {
      /* Higher testosterone: try to take over immediately (no courtesy sleep). */
      if (cas_u64_lock_cmpxchg(&slot->owner_tag, oldtag, mytag)) {
        __atomic_store_n(&slot->owner_meta, mymeta, __ATOMIC_RELEASE);
        tlogf(caller_level, "alpha lock – dominance asserted (takeover from level %d)", owner_level);
        return 1;
      }
      continue;
    }

    /* Lower testosterone: wait, then retry. */
    if (!slept) {
      tlogf(caller_level, "alpha lock – waiting in line behind level %d", owner_level);
      slept = 1;
    }
    usleep((useconds_t)((100 - caller_level) * 1000));
  }

  (void)fd;
  return 0;
}

static void alpha_release_owner(uint64_t inode) {
  if (!g_alpha) return;
  uint64_t ikey = inode_key48(inode);
  struct alpha_slot *slot = alpha_find_slot(ikey);
  if (!slot) return;

  uint16_t pid16 = (uint16_t)(getpid() & 0xFFFF);
  uint64_t mytag = (ikey << 16) | (uint64_t)pid16;

  (void)cas_u64_lock_cmpxchg(&slot->owner_tag, mytag, 0);
  __atomic_store_n(&slot->owner_meta, 0, __ATOMIC_RELEASE);
}

/* ----------------------- open + flock interposition ------------------------ */

int open(const char *pathname, int flags, ...) {
  resolve_symbols();
  if (!real_open) {
    errno = ENOSYS;
    return -1;
  }

  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
    return real_open(pathname, flags, mode);
  }
  return real_open(pathname, flags);
}

int flock(int fd, int operation) {
  resolve_symbols();
  if (!real_flock) {
    errno = ENOSYS;
    return -1;
  }

  /* Only special-case exclusive lock attempts. */
  if ((operation & LOCK_EX) == 0) {
    int rc = real_flock(fd, operation);
    if (rc == 0 && (operation & LOCK_UN)) {
      struct stat st;
      if (fstat(fd, &st) == 0) alpha_release_owner((uint64_t)st.st_ino);
    }
    return rc;
  }

  struct stat st;
  if (fstat(fd, &st) != 0) return real_flock(fd, operation);

  int level = testosterone_level();
  (void)alpha_acquire_owner(fd, (uint64_t)st.st_ino, level);

  /* Real kernel flock: higher levels retry more aggressively; lower levels nap. */
  int tries = 0;
  int op_nb = operation | LOCK_NB;
  for (;;) {
    int rc = real_flock(fd, op_nb);
    if (rc == 0) return 0;

    if (errno != EWOULDBLOCK && errno != EAGAIN) return rc;

    tries++;
    if (level <= 70) {
      usleep((useconds_t)((100 - level) * 1000));
    } else {
      /* Aggressive mode: short, frequent retries. */
      usleep(500);
    }

    if (tries > 200) {
      /* Fall back to blocking flock to preserve expected semantics. */
      return real_flock(fd, operation);
    }
  }
}

/* --------------------------- send/recv dominance --------------------------- */

#define SOCK_TABLE_SLOTS 4096u /* power of two */

struct sock_slot {
  _Atomic int fd;
  _Atomic uint8_t boosted;
};

static struct sock_slot g_sock[SOCK_TABLE_SLOTS];

__attribute__((constructor)) static void testosterone_ctor(void) {
  const char *c = getenv("TESTOSTERONE_COLOR");
  if (c && (*c == '0' || *c == 'n' || *c == 'N')) g_use_color = 0;

  /* Initialize socket tracking table with fd = -1. */
  for (uint32_t i = 0; i < SOCK_TABLE_SLOTS; i++) {
    __atomic_store_n(&g_sock[i].fd, -1, __ATOMIC_RELAXED);
    __atomic_store_n(&g_sock[i].boosted, 0, __ATOMIC_RELAXED);
  }
}

static bool sock_mark_first_time(int fd) {
  uint32_t h = ((uint32_t)fd * 2654435761u) & (SOCK_TABLE_SLOTS - 1u);
  for (uint32_t probe = 0; probe < SOCK_TABLE_SLOTS; probe++) {
    struct sock_slot *s = &g_sock[(h + probe) & (SOCK_TABLE_SLOTS - 1u)];
    int cur = __atomic_load_n(&s->fd, __ATOMIC_ACQUIRE);
    if (cur == fd) {
      uint8_t was = __atomic_exchange_n(&s->boosted, 1, __ATOMIC_ACQ_REL);
      return was == 0;
    }
    if (cur == -1) {
      int expect = -1;
      if (__atomic_compare_exchange_n(&s->fd, &expect, fd, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&s->boosted, 1, __ATOMIC_RELEASE);
        return true;
      }
    }
  }
  return false;
}

static void boost_socket_buffers(int fd, int level) {
  int add = level * 1024;
  int val = 0;
  socklen_t len = (socklen_t)sizeof(val);

  if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &len) == 0) {
    int newv = val + add;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &newv, (socklen_t)sizeof(newv));
  }
  len = (socklen_t)sizeof(val);
  if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len) == 0) {
    int newv = val + add;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &newv, (socklen_t)sizeof(newv));
  }

  tlogf(level, "Socket buffers boosted for dominance.");
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  resolve_symbols();
  if (!real_send) {
    errno = ENOSYS;
    return -1;
  }

  if (!g_in_hook && sockfd >= 0 && sock_mark_first_time(sockfd)) {
    int level = testosterone_level();
    g_in_hook++;
    boost_socket_buffers(sockfd, level);
    g_in_hook--;
  }

  return real_send(sockfd, buf, len, flags);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
  resolve_symbols();
  if (!real_recv) {
    errno = ENOSYS;
    return -1;
  }

  if (!g_in_hook && sockfd >= 0 && sock_mark_first_time(sockfd)) {
    int level = testosterone_level();
    g_in_hook++;
    boost_socket_buffers(sockfd, level);
    g_in_hook--;
  }

  return real_recv(sockfd, buf, len, flags);
}

/* Installed Linux supervisor. The compiler remains Kelft; this trusted host
 * component snapshots its pinned bundle and invokes the measured OS boundary.
 * No shell, Python, Node, compiler tool or engine is needed on the runtime
 * PATH. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
typedef struct {
  const char *path, *sha256;
  unsigned long long size;
  unsigned mode;
} PinnedFile;
typedef struct { const char *path, *target; } PinnedAlias;
#include "bundle-pins.h"
static void fail(const char *why) {
  fprintf(stderr, "error[K0600]: %s\n", why);
  exit(125);
}
typedef struct {
  uint32_t h[8];
  uint64_t bytes;
  unsigned used;
  unsigned char block[64];
} SHA;
static uint32_t rotate(uint32_t n, unsigned k) {
  return (n >> k) | (n << (32 - k));
}
static void compress(SHA *s) {
  static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t w[64];
  for (unsigned n = 0; n < 16; n++) {
    const unsigned char *p = s->block + n * 4;
    w[n] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
           p[3];
  }
  for (unsigned n = 16; n < 64; n++) {
    uint32_t a = w[n - 15], b = w[n - 2];
    w[n] = w[n - 16] + (rotate(a, 7) ^ rotate(a, 18) ^ (a >> 3)) + w[n - 7] +
           (rotate(b, 17) ^ rotate(b, 19) ^ (b >> 10));
  }
  uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4],
           f = s->h[5], g = s->h[6], h = s->h[7];
  for (unsigned n = 0; n < 64; n++) {
    uint32_t p = h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
                 ((e & f) ^ (~e & g)) + k[n] + w[n],
             q = (rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) +
                 ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + p;
    d = c;
    c = b;
    b = a;
    a = p + q;
  }
  uint32_t values[8] = {a, b, c, d, e, f, g, h};
  for (unsigned n = 0; n < 8; n++)
    s->h[n] += values[n];
}
static SHA sha_init(void) {
  return (SHA){.h = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                     0x9b05688c, 0x1f83d9ab, 0x5be0cd19}};
}
static void sha_update(SHA *s, const void *data, size_t n) {
  const unsigned char *p = data;
  s->bytes += n;
  while (n) {
    unsigned take = 64 - s->used;
    if (take > n)
      take = (unsigned)n;
    memcpy(s->block + s->used, p, take);
    s->used += take;
    p += take;
    n -= take;
    if (s->used == 64) {
      compress(s);
      s->used = 0;
    }
  }
}
static void sha_end(SHA *s, char out[65]) {
  uint64_t bits = s->bytes * 8;
  unsigned char one = 128, zero = 0;
  sha_update(s, &one, 1);
  while (s->used != 56)
    sha_update(s, &zero, 1);
  unsigned char length[8];
  for (unsigned n = 0; n < 8; n++)
    length[n] = (unsigned char)(bits >> (56 - 8 * n));
  sha_update(s, length, 8);
  static const char hex[] = "0123456789abcdef";
  for (unsigned n = 0; n < 32; n++) {
    unsigned byte = (s->h[n / 4] >> (24 - 8 * (n % 4))) & 255;
    out[n * 2] = hex[byte >> 4];
    out[n * 2 + 1] = hex[byte & 15];
  }
  out[64] = 0;
}
static char scratch[PATH_MAX];
static volatile sig_atomic_t stopped;
static void erase(int fd) {
  DIR *d = fdopendir(dup(fd));
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    int child =
        openat(fd, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child >= 0) {
      erase(child);
      close(child);
      unlinkat(fd, e->d_name, AT_REMOVEDIR);
    } else
      unlinkat(fd, e->d_name, 0);
  }
  closedir(d);
}
static void cleanup(void) {
  if (!scratch[0])
    return;
  int fd = open(scratch, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd >= 0) {
    erase(fd);
    close(fd);
    rmdir(scratch);
  }
  scratch[0] = 0;
}
static int parent_at(int root, const char *name, int create,
                     char leaf[NAME_MAX + 1]) {
  char copy[PATH_MAX];
  if (!name[0] || name[0] == '/' || strlen(name) >= sizeof copy)
    fail("invalid pinned bundle path");
  strcpy(copy, name);
  int fd = dup(root);
  if (fd < 0)
    fail("bundle root descriptor");
  char *part = copy;
  for (;;) {
    char *slash = strchr(part, '/');
    if (slash)
      *slash = 0;
    if (!*part || !strcmp(part, ".") || !strcmp(part, "..") ||
        strlen(part) > NAME_MAX)
      fail("invalid pinned path component");
    if (!slash) {
      strcpy(leaf, part);
      return fd;
    }
    if (create && mkdirat(fd, part, 0700) && errno != EEXIST)
      fail("snapshot directory");
    int next =
        openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    if (next < 0)
      fail("bundle parent alias or missing directory");
    fd = next;
    part = slash + 1;
  }
}
static void measured(int root, const PinnedFile *pin, int destination) {
  int mutable_compiler = 0;
#ifdef KELFT_REBUILD_COMPILER
  mutable_compiler = !strcmp(pin->path, "rootfs/compiler");
#endif
  char leaf[NAME_MAX + 1];
  int parent = parent_at(root, pin->path, 0, leaf),
      fd = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  close(parent);
  struct stat before, after;
  if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) ||
      (unsigned)(before.st_mode & 0777) != pin->mode || before.st_size < 0 ||
      (!mutable_compiler && (unsigned long long)before.st_size != pin->size) ||
      before.st_size > 268435456 || pin->size > 268435456)
    fail("pinned bundle file type, mode or size changed");
  int out = -1;
  if (destination >= 0) {
    int p = parent_at(destination, pin->path, 1, leaf);
    out = openat(p, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                 0600);
    close(p);
    if (out < 0)
      fail("snapshot file");
  }
  SHA s = sha_init();
  unsigned char buffer[65536];
  unsigned long long total = 0;
  for (;;) {
    if (stopped) { exit(128 + stopped); }
    ssize_t n = read(fd, buffer, sizeof buffer);
    if (n < 0 && errno == EINTR)
      continue;
    if (n < 0)
      fail("read pinned input");
    if (!n)
      break;
    total += (unsigned long long)n;
    if (total > (mutable_compiler ? (unsigned long long)before.st_size : pin->size))
      fail("pinned input grew");
    sha_update(&s, buffer, (size_t)n);
    size_t at = 0;
    while (out >= 0 && at < (size_t)n) {
      ssize_t wrote = write(out, buffer + at, (size_t)n - at);
      if (wrote < 0 && errno == EINTR)
        continue;
      if (wrote <= 0)
        fail("write snapshot");
      at += (size_t)wrote;
    }
  }
  char digest[65];
  sha_end(&s, digest);
  if (total != (mutable_compiler ? (unsigned long long)before.st_size : pin->size) ||
      (!mutable_compiler && strcmp(digest, pin->sha256)) || fstat(fd, &after) ||
      before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      before.st_size != after.st_size ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
      before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
    fail("pinned input changed while snapshotting");
  close(fd);
  if (out >= 0) {
    if (fchmod(out, pin->mode) || close(out))
      fail("snapshot mode");
  }
}
static void session_input(int source, int destination, const char *name,
                          unsigned long long maximum, int required) {
  char source_leaf[NAME_MAX+1];int source_parent=parent_at(source,name,0,source_leaf);
  int fd = openat(source_parent, source_leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);close(source_parent);
  if (fd < 0 && errno == ENOENT && !required) return;
  struct stat st;
  if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
      st.st_size < 0 || (unsigned long long)st.st_size > maximum)
    fail("invalid private protocol input");
  SHA sha = sha_init();
  unsigned char bytes[65536];
  for (;;) {
    ssize_t n = read(fd, bytes, sizeof bytes);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) fail("private protocol input read");
    if (!n) break;
    sha_update(&sha, bytes, (size_t)n);
    if (sha.bytes > maximum) fail("private protocol input bound");
  }
  char digest[65]; sha_end(&sha, digest); close(fd);
  PinnedFile pin = {name, digest, (unsigned long long)st.st_size,
                    (unsigned)st.st_mode & 0777};
  measured(source, &pin, destination);
}
static void check_host(int root) {
  for (unsigned n = 0; n < sizeof host_inputs / sizeof *host_inputs; n++) {
    measured(root, &host_inputs[n], -1);
  }
  for (unsigned n = 0; n < sizeof host_aliases / sizeof *host_aliases; n++) {
    char actual[PATH_MAX];
    if (!realpath(host_aliases[n].path, actual) || strcmp(actual, host_aliases[n].target)) {
      fail("pinned host boundary library alias changed");
    }
  }
}
static long long now(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    fail("monotonic clock");
  return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void stop(int sig) { stopped = sig; }
static int all_write(int fd, const char *data, size_t n, long long deadline) {
  while (n) {
    if (stopped || now() >= deadline)
      return -1;
    ssize_t done = write(fd, data, n);
    if (done < 0 && errno == EINTR)
      continue;
    if (done < 0 && errno == EAGAIN) {
      struct pollfd p = {.fd = fd, .events = POLLOUT};
      poll(&p, 1, 10);
      continue;
    }
    if (done <= 0)
      return -1;
    data += done;
    n -= (size_t)done;
  }
  return 0;
}
static unsigned long long supervision_timeout=600000, supervision_memory=1073741824,
  supervision_stdout=16777216, supervision_stderr=16777216, supervision_combined=16777216, supervision_file=67108864;
static int supervision_failure;
static int prepared_engine_fd=-1;
static int inherited_mounts[128];
static int candidate_host_fd=-1,candidate_input_fd=-1,candidate_signal=0,candidate_status_fd=-1;
static unsigned inherited_mount_count;
static int supervise(char **args) {
  if(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0))fail("descendant reaper");
  int pipes[2][2];
  if (pipe2(pipes[0], O_CLOEXEC) || pipe2(pipes[1], O_CLOEXEC))
    fail("capture pipes");
  signal(SIGPIPE, SIG_IGN);
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  signal(SIGHUP, stop);
  pid_t owner = getpid();
  pid_t child = fork();
  if (child < 0)
    fail("supervisor fork");
  if (!child) {
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != owner ||
        setpgid(0, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
      _exit(125);
    struct rlimit limits[] = {{supervision_memory, supervision_memory},
                              {16777216, 16777216},
                              {supervision_file, supervision_file},
                              {256, 256},
                              {(supervision_timeout+999)/1000, (supervision_timeout+999)/1000}};
    int resources[] = {RLIMIT_AS, RLIMIT_STACK, RLIMIT_FSIZE, RLIMIT_NOFILE,
                       RLIMIT_CPU};
    for (unsigned n = 0; n < 5; n++)
      if (setrlimit(resources[n], &limits[n]))
        _exit(125);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core))
      _exit(125);
    int input = candidate_input_fd>=0?candidate_input_fd:open("/dev/null", O_RDONLY);
    if (input < 0 || dup2(input, 0) < 0 || dup2(pipes[0][1], 1) < 0 ||
        dup2(pipes[1][1], 2) < 0 || syscall(SYS_close_range, 3U, ~0U, 4))
      _exit(125);
    for(unsigned n=0;n<inherited_mount_count;n++)
      if(fcntl(inherited_mounts[n],F_SETFD,0)<0)_exit(125);
    if(candidate_host_fd>=0&&fcntl(candidate_host_fd,F_SETFD,0)<0)_exit(125);
    if(candidate_status_fd>=0&&fcntl(candidate_status_fd,F_SETFD,0)<0)_exit(125);
    if(prepared_engine_fd>=0&&dup3(prepared_engine_fd,3,0)<0)_exit(125);
    char *environment[] = {"PATH=/usr/bin:/bin", "LC_ALL=C", NULL};
    execve(args[0], args, environment);
    _exit(125);
  }
  setpgid(child, child);
  int original[2];
  struct pollfd fds[2];
  for (int n = 0; n < 2; n++) {
    close(pipes[n][1]);
    fds[n] = (struct pollfd){.fd = pipes[n][0], .events = POLLIN};
    original[n] = fcntl(n + 1, F_GETFL);
    if (original[n] < 0 ||
        fcntl(n + 1, F_SETFL, original[n] | O_NONBLOCK) < 0 ||
        fcntl(fds[n].fd, F_SETFL, O_NONBLOCK) < 0)
      fail("nonblocking capture");
  }
  long long deadline = now() + (long long)supervision_timeout;
  int status = 0, finished = 0, bounded = 0;
  size_t total = 0, captured[2] = {0,0};
  char buffer[8192];
  while (!finished || fds[0].fd >= 0 || fds[1].fd >= 0) {
    long long left = deadline - now();
    if (left <= 0 || stopped) {
      bounded = stopped ? 128 + stopped : 124;
      break;
    }
    int ready = poll(fds, 2, left > 50 ? 50 : (int)left);
    if (ready < 0 && errno != EINTR) {
      bounded = 125;
      break;
    }
    for (int n = 0; n < 2 && !bounded; n++)
      if (fds[n].fd >= 0 && (fds[n].revents & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t got = read(fds[n].fd, buffer, sizeof buffer);
        if (got > 0) {
          size_t accepted = (size_t)got;
          size_t stream_limit=(size_t)(n?supervision_stderr:supervision_stdout);
          if(accepted>stream_limit-captured[n])accepted=stream_limit-captured[n];
          if(accepted>(size_t)supervision_combined-total)accepted=(size_t)supervision_combined-total;
          if (all_write(n + 1, buffer, accepted, deadline)) {
            bounded = stopped ? 128 + stopped : now() >= deadline ? 124 : 125;
            break;
          }
          total += accepted; captured[n] += accepted;
          if (accepted != (size_t)got)
            bounded = 122;
        } else if (!got) {
          close(fds[n].fd);
          fds[n].fd = -1;
        } else if (errno != EAGAIN && errno != EINTR)
          bounded = 125;
      }
    if (bounded)
      break;
    if (!finished) {
      pid_t done = waitpid(child, &status, WNOHANG);
      if (done == child)
        finished = 1;
      else if (done < 0 && errno != EINTR) {
        bounded = 125;
        break;
      }
    }
  }
  if (bounded) {
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
  }
  if (!finished)
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
  /* Adopt namespace helpers when an interrupted boundary exits before them. */
  long long reap_until=now()+1000;
  for(;;){int orphan;pid_t done=waitpid(-1,&orphan,WNOHANG);
    if(done>0)continue;
    if(done<0&&errno==EINTR)continue;
    if(done<0&&errno==ECHILD)break;
    if(now()>=reap_until){bounded=125;break;}
    struct timespec pause={0,1000000};nanosleep(&pause,NULL);
  }
  for (int n = 0; n < 2; n++) {
    if (fds[n].fd >= 0)
      close(fds[n].fd);
    if (fcntl(n + 1, F_SETFL, original[n]) < 0)
      bounded = 125;
  }
  supervision_failure=bounded;
  if (bounded)
    return bounded;
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  candidate_signal=WIFSIGNALED(status)?WTERMSIG(status):0;
  supervision_failure=candidate_signal?128+candidate_signal:125;
  return supervision_failure;
}
static void beneath(const char *root, const char *file, char guest[PATH_MAX]) {
  char actual[PATH_MAX];
  if (!realpath(file, actual))
    fail("input path missing");
  size_t n = strlen(root);
  if (strncmp(actual, root, n) || actual[n] != '/')
    fail("input must be below --project-root");
  if (snprintf(guest, PATH_MAX, "/project%s", actual + n) >= PATH_MAX)
    fail("input path length");
}
#include "candidate.h"
#include "cross.h"
int main(int argc, char **argv) {
  int supplied_bundle=-1;
  if(argc>=3&&!strcmp(argv[1],"--installed-root-fd")){
    supplied_bundle=(int)candidate_number(argv[2],1048576);
    struct stat st;if(supplied_bundle<3||fstat(supplied_bundle,&st)||!S_ISDIR(st.st_mode))fail("installed root descriptor");
    memmove(argv+1,argv+3,(size_t)(argc-2)*sizeof(*argv));argc-=2;
  }
  if(argc>=2&&!strcmp(argv[1],"--engine-worker"))return engine_worker(argc,argv);
  if(argc>=2&&!strcmp(argv[1],"--candidate-worker"))return candidate_worker(argc,argv);
  if (argc == 2 && !strcmp(argv[1], "--sha256-self-test")) {
    const char *inputs[] = {
        "", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    const char *outputs[] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"};
    for (unsigned n = 0; n < 3; n++) {
      SHA s = sha_init();
      sha_update(&s, inputs[n], strlen(inputs[n]));
      char out[65];
      sha_end(&s, out);
      if (strcmp(out, outputs[n]))
        fail("SHA-256 vector");
    }
    SHA s = sha_init();
    for (unsigned n = 0; n < 1000000; n++)
      sha_update(&s, "a", 1);
    char out[65];
    sha_end(&s, out);
    if (strcmp(
            out,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"))
      fail("SHA-256 million-byte vector");
    puts("sha256-self-test-ok");
    return 0;
  }
  if (getuid() == 0 || geteuid() != getuid()) {
    fail("ordinary non-root user required");
  }
  signal(SIGTERM, stop);
  signal(SIGINT, stop);
  signal(SIGHUP, stop);
  if(supplied_bundle==3){supplied_bundle=fcntl(supplied_bundle,F_DUPFD_CLOEXEC,4);if(supplied_bundle<0)fail("installed root reservation");}
  if(dup3(0,3,O_CLOEXEC)<0)fail("private engine descriptor reservation");
  if(argc>=3&&!strcmp(argv[1],"candidate-run"))return candidate_run(argc,argv);
  int protocol = argc > 3 && !strcmp(argv[1], "protocol");
  int engine = argc > 3 && !strcmp(argv[1], "engine-run");
  int inspect = argc > 2 && (!strcmp(argv[1], "check") || !strcmp(argv[1], "tokens") ||
      !strcmp(argv[1], "ast") || !strcmp(argv[1], "ir"));
  int cross = argc > 2 && (!strcmp(argv[1],"cross-object")||!strcmp(argv[1],"cross-build"));
  int cross_build = cross && !strcmp(argv[1],"cross-build");
  int object = argc > 2 && (!strcmp(argv[1], "native-object")||cross);
  if(cross_build){
#ifndef KELFT_LINUX_WINDOWS_CROSS_SHA256
    fail("offline Linux-to-Windows profile is not installed");
#endif
  }
  if (argc < 4 || (!protocol && !engine && !inspect && !object && strcmp(argv[1], "native-build")))
    fail("expected native-build, protocol prepare/finalize, or engine-run");
  if (protocol && strcmp(argv[2], "prepare") && strcmp(argv[2], "finalize"))
    fail("unknown protocol phase");
  if (engine) {
    supervision_file=268435456;
    /* Engine address spaces include V8/Wasmtime reservations. Compiler-only
     * invocations retain their independent 1 GiB address-space ceiling. */
    supervision_memory=!strcmp(argv[2],"javascript")?4294967296ULL:17179869184ULL;
  }
  if (engine && strcmp(argv[2], "javascript") && strcmp(argv[2], "wasm"))
    fail("unknown optional engine");
  const char *root_arg = NULL, *output_arg = NULL, *caps = NULL, *intent = NULL,
             *bindings = NULL, *control_arg = NULL, *fixtures_arg = NULL,
             *ledger_arg = NULL, *artifact_target = NULL, *object_output_arg = NULL;
  const char *engine_roots[128];int engine_writes[128];unsigned engine_count=0;
  int tail = argc;
  for (int n = protocol || engine ? 4 : 3; n < argc; n += 2) {
    if (engine && !strcmp(argv[n], "--")) { tail = n + 1; break; }
    if (n + 1 >= argc) fail("missing option value");
    if(!engine&&!protocol&&!strncmp(argv[n],"--host-",7)){
      unsigned long long value=candidate_number(argv[n+1],1073741824ULL);
      if(!strcmp(argv[n],"--host-memory-bytes")&&value>=16777216&&value<=1073741824ULL)supervision_memory=value;
      else if(!strcmp(argv[n],"--host-timeout-ms")&&value>0&&value<=600000)supervision_timeout=value;
      else if(!strcmp(argv[n],"--host-stdout-bytes")&&value<=16777216)supervision_stdout=value;
      else if(!strcmp(argv[n],"--host-stderr-bytes")&&value<=16777216)supervision_stderr=value;
      else fail("invalid bounded compiler envelope");
      continue;
    }
    if(engine&&(!strcmp(argv[n],"--read")||!strcmp(argv[n],"--write"))){
      if(engine_count>=128)fail("engine grant count");
      engine_roots[engine_count]=argv[n+1];engine_writes[engine_count++]=!strcmp(argv[n],"--write");continue;
    }
    const char **slot = NULL;
    if (!strcmp(argv[n], "--project-root")) slot = &root_arg;
    else if (!strcmp(argv[n], "--artifact-target") && cross) slot = &artifact_target;
    else if (!strcmp(argv[n], "-o") && !protocol && !engine && !inspect) slot = &output_arg;
    else if (!strcmp(argv[n], "--object-output") && !protocol && !engine && !inspect && !object) slot = &object_output_arg;
    else if (!strcmp(argv[n], "--output-root") && (protocol || engine)) slot = &output_arg;
    else if ((!strcmp(argv[n], "--capabilities") && !protocol && !engine) ||
             (!strcmp(argv[n], "--policy") && engine)) slot = &caps;
    else if (!strcmp(argv[n], "--intent") && !protocol && !engine) slot = &intent;
    else if (!strcmp(argv[n], "--bindings") && !protocol && !engine) slot = &bindings;
    else if (!strcmp(argv[n], "--control-root") && protocol) slot = &control_arg;
    else if (!strcmp(argv[n], "--fixtures-root") && protocol) slot = &fixtures_arg;
    else if (!strcmp(argv[n], "--ledger-root") && protocol) slot = &ledger_arg;
    else fail("unsupported option");
    if (*slot) fail("duplicate option");
    *slot = argv[n + 1];
  }
  if (!root_arg || (!engine && !inspect && !output_arg) ||
      (protocol && (!control_arg || !fixtures_arg))) fail("missing profile roots");
  if(cross){
#if defined(__x86_64__)
    if(!artifact_target||strcmp(artifact_target,"windows-x86_64"))fail("unsupported cross artifact target");
#else
    fail("unsupported cross compiler host");
#endif
  }
  char project[PATH_MAX], entry[PATH_MAX], outdir[PATH_MAX] = "", output[PATH_MAX],
       guest_caps[PATH_MAX], guest_intent[PATH_MAX], guest_bindings[PATH_MAX],
       fixtures[PATH_MAX], ledger[PATH_MAX], guest_output[PATH_MAX], guest_object_output[PATH_MAX];
  if (!realpath(root_arg, project) || !strcmp(project, "/")) fail("invalid project root");
  struct stat project_info;
  if (stat(project, &project_info) || !S_ISDIR(project_info.st_mode)) fail("project root is not a directory");
  if(cross&&(grant_contains(project,"/tmp")||!strncmp(project,"/tmp/kelft-standalone-",strlen("/tmp/kelft-standalone-"))))fail("cross project overlaps private temporary state");
  if (!protocol) beneath(project, argv[engine ? 3 : 2], entry);
  if (caps) beneath(project, caps, guest_caps);
  if (intent) beneath(project, intent, guest_intent);
  if (bindings) beneath(project, bindings, guest_bindings);
  if (protocol || engine) {
    if (output_arg && (!realpath(output_arg, outdir) || !strcmp(outdir, "/"))) fail("invalid output root");
    if (output_arg && (stat(outdir, &project_info) || !S_ISDIR(project_info.st_mode))) fail("output root is not a directory");
    if (protocol) {
      char control[PATH_MAX], request[PATH_MAX];
      if (!realpath(control_arg, control) || !strcmp(control, "/") ||
          !realpath(argv[3], request) || strncmp(request, control, strlen(control)) ||
          strcmp(request + strlen(control), "/request.json")) fail("request must be control-root/request.json");
      if (!realpath(fixtures_arg, fixtures) || !strcmp(fixtures, "/") ||
          stat(fixtures, &project_info) || !S_ISDIR(project_info.st_mode)) fail("invalid fixtures root");
      if (ledger_arg && (!realpath(ledger_arg, ledger) || !strcmp(ledger, "/") ||
          stat(ledger, &project_info) || !S_ISDIR(project_info.st_mode))) fail("invalid ledger root");
    }
  } else if (!inspect) {
    if (strlen(output_arg) >= sizeof output) fail("output path length");
    strcpy(output, output_arg);
    char *slash = strrchr(output, '/'); const char *base = slash ? slash + 1 : output;
    char basename[NAME_MAX + 1];
    if (!*base || !strcmp(base, ".") || !strcmp(base, "..") || strlen(base) > NAME_MAX) fail("invalid output name");
    strcpy(basename, base);
    if (slash) {
      if (slash == output) strcpy(outdir, "/");
      else { *slash = 0; if (!realpath(output, outdir)) fail("output directory must exist"); }
    } else if (!getcwd(outdir, sizeof outdir)) fail("output directory");
    if (!strcmp(outdir, "/")) fail("root output directory rejected");
    if (snprintf(guest_output, sizeof guest_output, "/out/%s", basename) >= (int)sizeof guest_output) fail("output path length");
    if (object_output_arg) {
      char object_path[PATH_MAX], object_parent[PATH_MAX], object_directory[PATH_MAX];
      if (strlen(object_output_arg) >= sizeof object_path) fail("object output path length");
      strcpy(object_path, object_output_arg);
      char *object_slash = strrchr(object_path, '/');
      const char *object_name = object_slash ? object_slash + 1 : object_path;
      size_t object_length = strlen(object_name);
      if (!object_length || object_length > NAME_MAX || !strcmp(object_name,".") || !strcmp(object_name,"..") ||
          !strcmp(object_name,basename) || (object_length >= 6 && !strcmp(object_name+object_length-6,".kelft")))
        fail("object output must be distinct from executable and source inputs");
      if (snprintf(guest_object_output,sizeof guest_object_output,"/out/%s",object_name) >= (int)sizeof guest_object_output) fail("object output path length");
      if (object_slash) { if(object_slash==object_path) strcpy(object_parent,"/"); else {*object_slash=0;strcpy(object_parent,object_path);} }
      else strcpy(object_parent,".");
      if (!realpath(object_parent,object_directory) || strcmp(object_directory,outdir)) fail("object output must share the authorized output directory");
    }
  }
  char executable[PATH_MAX], bundle[PATH_MAX];
  if(supplied_bundle<0){
  ssize_t length =
      readlink("/proc/self/exe", executable, sizeof executable - 1);
  if (length <= 0 || length >= (ssize_t)sizeof executable - 1)
    fail("installed executable path");
  executable[length] = 0;
  char *last = strrchr(executable, '/');
  if (!last)
    fail("installed executable directory");
  *last = 0;
  last = strrchr(executable, '/');
  if (!last || strcmp(last + 1, "bin"))
    fail("install supervisor below bin/");
  *last = 0;
  strcpy(bundle, executable);
  }
  int root = supplied_bundle>=0?fcntl(supplied_bundle,F_DUPFD_CLOEXEC,3):open(bundle, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
      host = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root < 0 || host < 0)
    fail("bundle root");
  check_host(host);
#ifdef KELFT_TARGET_COMPONENTS
  char lock_leaf[NAME_MAX+1];int lock_parent=parent_at(root,".kelft-targets/lock",0,lock_leaf);
  int component_lock=openat(lock_parent,lock_leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(lock_parent);
  if(component_lock<0||flock(component_lock,LOCK_SH))fail("component build lock");
#endif
#ifdef KELFT_LINUX_WINDOWS_CROSS_SHA256
  if(cross_build){
#ifdef KELFT_TARGET_COMPONENTS
    char receipt_leaf[NAME_MAX+1];int receipt_parent=parent_at(root,".kelft-targets/windows-x86_64.receipt",0,receipt_leaf);
    int receipt=openat(receipt_parent,receipt_leaf,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);close(receipt_parent);
    char activation[130];ssize_t length=receipt<0?-1:read(receipt,activation,sizeof activation);if(receipt>=0)close(receipt);
    if(length!=(ssize_t)strlen(KELFT_TARGET_RECEIPT)||memcmp(activation,KELFT_TARGET_RECEIPT,(size_t)length))fail("target pack is inactive; use kelft target add x86_64-windows --from PACK.tar.gz");
#endif
    char destination[PATH_MAX],actual[PATH_MAX];
    const char *base=strrchr(guest_output,'/');if(!base||!base[1]||(strlen(base+1)>=6&&!strcasecmp(base+strlen(base)-6,".kelft")))fail("invalid cross output name");
    if(snprintf(destination,sizeof destination,"%s/%s",outdir+1,base+1)>=(int)sizeof destination)fail("cross output bound");
    cross_output_parent=parent_at(host,destination,0,cross_output_leaf);
    if(realpath(output_arg,actual)){
      char source[PATH_MAX];if(!realpath(argv[2],source)||!strcmp(actual,source))fail("cross output overlaps source");
      const char *inputs[]={caps,intent,bindings};for(unsigned n=0;n<3;n++)if(inputs[n]&&realpath(inputs[n],source)&&!strcmp(actual,source))fail("cross output overlaps compiler input");
    }
  }
#endif
  strcpy(scratch, "/tmp/kelft-standalone-XXXXXX");
  if (!mkdtemp(scratch))
    fail("private package snapshot");
  if (atexit(cleanup))
    fail("snapshot cleanup handler");
#ifdef KELFT_LINUX_WINDOWS_CROSS_SHA256
  if(cross_build){char objects[PATH_MAX];cross_directory("cross-objects",objects);if(mkdir(objects,0700))fail("cross object directory");}
#endif
  int snapshot = open(scratch, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (snapshot < 0)
    fail("snapshot root");
  const char *profile_root = !engine ? "rootfs" :
      !strcmp(argv[2], "javascript") ? "engines/javascript" : "engines/wasm";
  size_t profile_length = strlen(profile_root);
  unsigned selected = 0;
  for (unsigned n = 0; n < sizeof bundle_files / sizeof *bundle_files; n++) {
    const char *name = bundle_files[n].path;
    if ((!strncmp(name, profile_root, profile_length) && name[profile_length] == '/') ||
        !strcmp(name, "manifest.json") || !strcmp(name, "supervisor.json")
#ifdef KELFT_LINUX_WINDOWS_CROSS_SHA256
        ||(cross_build&&!strncmp(name,cross_prefix,strlen(cross_prefix)))
#endif
        ) {
      measured(root, &bundle_files[n], snapshot);
      if (strncmp(name, profile_root, profile_length) == 0) selected++;
    }
  }
  if (!selected) fail("optional engine profile is not installed");
  for (unsigned n = 0; n < sizeof empty_directories / sizeof *empty_directories;
       n++) {
    char relative[PATH_MAX], leaf[NAME_MAX + 1];
    const char *suffix = empty_directories[n];
    if (strncmp(suffix, "rootfs/", 7)) fail("invalid profile directory");
    if (snprintf(relative, sizeof relative, "%s/%s", profile_root, suffix + 7) >= (int)sizeof relative) fail("profile directory length");
    int parent = parent_at(snapshot, relative, 1, leaf);
    if (mkdirat(parent, leaf, 0700) && errno != EEXIST)
      fail("empty snapshot directory");
    close(parent);
  }
  close(root);
  close(snapshot);
#ifdef KELFT_LINUX_WINDOWS_CROSS_SHA256
  if(cross_build){cross_directory("cross-objects",outdir);strcpy(guest_output,"/out/target.obj");}
#endif
  char rootfs[PATH_MAX];
  if (snprintf(rootfs, sizeof rootfs, "%s/%s", scratch, profile_root) >=
      (int)sizeof rootfs)
    fail("snapshot path");
  if (protocol) {
    char destination[PATH_MAX];
    if (snprintf(destination, sizeof destination, "%s/control", rootfs) >= (int)sizeof destination) fail("control path length");
    int from = open(control_arg, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC),
        to = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (from < 0 || to < 0) fail("private control roots");
    session_input(from, to, "request.json", 1048576, 1);
    session_input(from, to, "session.key", 32, 1);
    session_input(from, to, "policy.json", 1048576, 1);
    session_input(from, to, "plan.json", 16777216, !strcmp(argv[2], "finalize"));
    session_input(from, to, "evidence.json", 16777216, !strcmp(argv[2], "finalize"));
    close(from); close(to);
  }
  char engine_sources[128][64],engine_guests[128][PATH_MAX],snapshot_entry[PATH_MAX],snapshot_policy[PATH_MAX];
  if(engine){
    char target[PATH_MAX];if(snprintf(target,sizeof target,"%s/project",rootfs)>=(int)sizeof target)fail("engine input root");
    int from=open(project,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),to=open(target,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(from<0||to<0)fail("engine source roots");
    session_input(from,to,entry+9,33554432,1);if(caps)session_input(from,to,guest_caps+9,1048576,1);
    if(snprintf(snapshot_entry,sizeof snapshot_entry,"%s%s",rootfs,entry)>=(int)sizeof snapshot_entry)fail("engine artifact snapshot");
    if(caps&&snprintf(snapshot_policy,sizeof snapshot_policy,"%s%s",rootfs,guest_caps)>=(int)sizeof snapshot_policy)fail("engine policy snapshot");
    for(unsigned n=0;n<engine_count;n++){
      char actual[PATH_MAX],leaf[NAME_MAX+1];int fd;
      if(!realpath(engine_roots[n],actual))fail("engine grant missing");
      if(grant_contains(actual,"/tmp"))fail("engine grant overlaps private temporary state");
      if(!strcmp(actual,project)){strcpy(engine_guests[n],"/project");fd=openat(from,".",O_PATH|O_NOFOLLOW|O_CLOEXEC);}
      else {beneath(project,actual,engine_guests[n]);int parent=parent_at(from,engine_guests[n]+9,0,leaf);fd=openat(parent,leaf,O_PATH|O_NOFOLLOW|O_CLOEXEC);close(parent);}
      struct stat st;if(fd<0||fstat(fd,&st)||!S_ISDIR(st.st_mode))fail("engine grant directory");inherited_mounts[inherited_mount_count++]=fd;
      if(snprintf(engine_sources[n],sizeof engine_sources[n],"/proc/self/fd/%d",fd)>=(int)sizeof engine_sources[n])fail("engine descriptor path");
      if(strcmp(engine_guests[n],"/project")){int parent=parent_at(to,engine_guests[n]+9,1,leaf);if(mkdirat(parent,leaf,0700)&&errno!=EEXIST)fail("engine mount directory");close(parent);}
    }
    close(from);close(to);
  }
  if(engine){
    char wanted[PATH_MAX],relative[PATH_MAX];
    if(snprintf(wanted,sizeof wanted,"%s/control/engines/%s",profile_root,argv[2])>=(int)sizeof wanted||
       snprintf(relative,sizeof relative,"control/engines/%s",argv[2])>=(int)sizeof relative)fail("engine image path");
    const PinnedFile *pin=NULL;for(unsigned n=0;n<sizeof bundle_files/sizeof *bundle_files;n++)if(!strcmp(bundle_files[n].path,wanted))pin=&bundle_files[n];
    if(!pin)fail("engine image pin missing");
    int rootfd=open(rootfs,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    prepared_engine_fd=seal_engine(rootfd,relative,pin);close(rootfd);
  }
  char engine_worker_path[PATH_MAX];if(engine){
    snapshot_worker(engine_worker_path);
    int rootfd=open(rootfs,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    int placeholder=rootfd<0?-1:openat(rootfd,"worker",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(placeholder<0||close(placeholder))fail("engine worker mount point");
    close(rootfd);
  }
  char *arguments[1024];
  unsigned count = 0;
#define ARG(s)                                                                 \
  do {                                                                         \
    if (count >= 1023)                                                          \
      fail("argument bound");                                                  \
    arguments[count++] = (char *)(s);                                          \
  } while (0)
  ARG(BWRAP_PATH);
  ARG("--unshare-user");
  ARG("--unshare-pid");
  ARG("--unshare-net");
  ARG("--unshare-ipc");
  ARG("--unshare-uts");
  ARG("--die-with-parent");
  ARG("--new-session");
  ARG("--ro-bind");
  ARG(rootfs);
  ARG("/");
  if(!engine){ARG("--ro-bind");ARG(project);ARG("/project");}
  else {
    for(unsigned n=0;n<engine_count;n++){ARG(engine_writes[n]?"--bind":"--ro-bind");ARG(engine_sources[n]);ARG(engine_guests[n]);}
    ARG("--ro-bind");ARG(snapshot_entry);ARG(entry);
    if(caps){ARG("--ro-bind");ARG(snapshot_policy);ARG(guest_caps);}
  }
  if(engine){ARG("--ro-bind");ARG(engine_worker_path);ARG("/worker");}
  if (outdir[0]) { ARG("--bind"); ARG(outdir); ARG("/out"); }
  if (protocol) {
    ARG("--ro-bind"); ARG(fixtures); ARG("/fixtures");
    if (ledger_arg) { ARG("--bind"); ARG(ledger); ARG("/out/ledger"); }
  }
  ARG("--proc");
  ARG("/proc");
  ARG("--dev");
  ARG("/dev");
  ARG("--chdir");
  ARG("/project");
  ARG("--clearenv");
  ARG("--setenv");
  ARG("KELFT_CAPABILITIES");
  ARG(engine?ENGINE_POLICY:inspect?"{\"read\":[\"/project\"],\"write\":[],\"execute\":false}":object?"{\"read\":[\"/project\",\"/out\"],\"write\":[\"/out\"],\"execute\":false}":COMPILER_POLICY);
  if(engine){ARG("--setenv");ARG(!strcmp(argv[2],"javascript")?"KELFT_JAVASCRIPT_RUNTIME_FD":"KELFT_WASM_RUNTIME_FD");ARG("3");}
  ARG("--");
  if(engine){
    ARG("/worker");ARG("--engine-worker");
    ARG("--read");ARG(entry);
    if(caps){ARG("--read");ARG(guest_caps);}
    for(unsigned n=0;n<engine_count;n++){ARG(engine_writes[n]?"--write":"--read");ARG(engine_guests[n]);}
    if(outdir[0]){ARG("--read");ARG("/out");ARG("--write");ARG("/out");}
    ARG("--");
  }
  ARG("/compiler");
  if (protocol) {
    ARG("protocol"); ARG(argv[2]); ARG("/control/request.json");
  } else if (engine) {
    ARG("engine-run"); ARG(argv[2]); ARG(entry);
    if (caps) { ARG("--policy"); ARG(guest_caps); }
    ARG("--"); for (int n = tail; n < argc; n++) ARG(argv[n]);
  } else {
    ARG(inspect?argv[1]:cross?"cross-object":object?"native-object":"native-build"); ARG(entry); ARG("--project-root"); ARG("/project");
    if(cross){ARG("--artifact-target");ARG("windows-x86_64");}
    if (!inspect && !object) { ARG("--toolchain"); ARG("/control/toolchain.json"); }
    if (!inspect) { ARG("-o"); ARG(guest_output); }
    if (object_output_arg) { ARG("--object-output"); ARG(guest_object_output); }
    if (caps) { ARG("--capabilities"); ARG(guest_caps); }
    if (intent) { ARG("--intent"); ARG(guest_intent); }
    if (bindings) { ARG("--bindings"); ARG(guest_bindings); }
  }
  arguments[count] = NULL;
  int result = supervise(arguments);
#ifdef KELFT_LINUX_WINDOWS_CROSS_SHA256
  if(cross_build&&result==0)result=cross_link();
#endif
  check_host(host);
  close(host);
  return result;
}

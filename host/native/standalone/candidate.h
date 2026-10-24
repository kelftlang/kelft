/* Private native candidate boundary. Included after the measured supervisor
 * primitives; the candidate receives neither the compiler nor session state. */
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
static unsigned long long candidate_number(const char *text, unsigned long long maximum) {
  if (!*text) fail("missing candidate limit");
  unsigned long long n = 0;
  for (const char *p = text; *p; p++) {
    if (*p < '0' || *p > '9' || n > (maximum - (unsigned)(*p - '0')) / 10)
      fail("invalid candidate limit");
    n = n * 10 + (unsigned)(*p - '0');
  }
  if (n > maximum) fail("candidate limit bound");
  return n;
}
/* Landlock is needed for a write grant without an enclosing read grant:
 * an ordinary writable bind mount also permits reading existing files. Older
 * kernels can still execute read-only or explicitly read/write profiles. */
static int grant_contains(const char *parent, const char *child) {
  size_t n=strlen(parent);
  return !strncmp(parent,child,n) && (!child[n] || child[n]=='/');
}
static void filesystem_grants(unsigned count, char **paths, int *writes,
                              int engine) {
  int abi=(int)syscall(SYS_landlock_create_ruleset,NULL,0,1);
  if(abi<3) {
    for(unsigned n=0;n<count;n++) if(writes[n]) {
      unsigned r;for(r=0;r<count;r++)
        if(!writes[r] && grant_contains(paths[r],paths[n]))break;
      if(r==count)fail("write-only filesystem grants require Landlock ABI 3 or newer");
    }
    if(candidate_host_fd>=0)fail("host execution requires Landlock ABI 3 or newer");
    return;
  }
  const unsigned long long read_file=1ULL<<2,read_dir=1ULL<<3;
  const unsigned long long write_bits=(1ULL<<1)|(1ULL<<4)|(1ULL<<5)|
    (1ULL<<7)|(1ULL<<8)|(1ULL<<13)|(1ULL<<14);
  struct {unsigned long long handled;} ruleset={read_file|read_dir|write_bits|(candidate_host_fd>=0?1ULL:0)|
    (1ULL<<6)|(1ULL<<9)|(1ULL<<10)|(1ULL<<11)|(1ULL<<12)};
  int fd=(int)syscall(SYS_landlock_create_ruleset,&ruleset,sizeof ruleset,0);
  if(fd<0)fail("filesystem ruleset");
  const char *common[]={"/proc","/dev/null","/dev/zero","/dev/urandom","/dev/random","/candidate","/worker"};
  const char *runtime[]={"/compiler","/worker","/control","/lib","/lib64","/usr/lib"};
  for(unsigned n=0;n<count+7+(engine?6:0);n++) {
    const char *path=n<count?paths[n]:n<count+7?common[n-count]:runtime[n-count-7];
    int write=n<count?writes[n]:!strcmp(path,"/dev/null");
    int root=open(path,O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if(root<0&&n>=count&&errno==ENOENT)continue;
    struct stat st;if(root<0||fstat(root,&st)||S_ISLNK(st.st_mode))fail("filesystem rule root");
    unsigned long long rights=write?(write_bits|read_dir):(read_file|read_dir);
    if(n>=count)rights|=read_file;
    if(candidate_host_fd>=0&&(!strcmp(path,"/candidate")||!strcmp(path,"/worker")))rights|=1ULL;
    if(!S_ISDIR(st.st_mode))rights&=read_file|(1ULL<<1)|(1ULL<<14)|1ULL;
    struct __attribute__((packed)) {unsigned long long allowed;int parent;} rule={rights,root};
    if(syscall(SYS_landlock_add_rule,fd,1,&rule,0))fail("filesystem rule");
    close(root);
  }
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||syscall(SYS_landlock_restrict_self,fd,0))fail("filesystem restriction");
  close(fd);
}
static int worker_grants(int argc,char **argv,int engine) {
  char *paths[258];int writes[258];unsigned count=0;int n=2;
  for(;n<argc&&strcmp(argv[n],"--");n+=2) {
    if(n+1<argc&&!strcmp(argv[n],"--host-fd")){if(candidate_host_fd>=0||strcmp(argv[n+1],"63"))fail("worker host descriptor");candidate_host_fd=63;struct stat socket;if(fstat(63,&socket)||!S_ISSOCK(socket.st_mode))fail("worker host socket");continue;}
    if(n+1<argc&&!strcmp(argv[n],"--status-fd")){if(candidate_status_fd>=0||strcmp(argv[n+1],"61"))fail("worker status descriptor");candidate_status_fd=61;continue;}
    if(n+1>=argc||count>=258||(strcmp(argv[n],"--read")&&strcmp(argv[n],"--write")))fail("worker filesystem grants");
    paths[count]=argv[n+1];writes[count++]=!strcmp(argv[n],"--write");
  }
  if(n==argc)fail("worker separator");
  filesystem_grants(count,paths,writes,engine);
  return n+1;
}
static void snapshot_worker(char worker[PATH_MAX]) {
  int self=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);
  if(self<0||snprintf(worker,PATH_MAX,"%s/worker",scratch)>=PATH_MAX)fail("worker snapshot path");
  int copy=open(worker,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0700);if(copy<0)fail("worker snapshot");
  char buffer[65536];size_t total=0;
  for(;;){ssize_t n=read(self,buffer,sizeof buffer);if(n<0&&errno==EINTR)continue;if(n<0)fail("worker snapshot read");if(!n)break;total+=(size_t)n;if(total>67108864)fail("worker snapshot bound");size_t at=0;while(at<(size_t)n){ssize_t done=write(copy,buffer+at,(size_t)n-at);if(done<0&&errno==EINTR)continue;if(done<=0)fail("worker snapshot write");at+=(size_t)done;}}
  close(self);if(close(copy))fail("worker snapshot close");
}
static int seal_engine(int root,const char *name,const PinnedFile *pin) {
  char leaf[NAME_MAX+1];int parent=parent_at(root,name,0,leaf);
  int input=openat(parent,leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);close(parent);
  struct stat st;if(input<0||fstat(input,&st)||!S_ISREG(st.st_mode)||st.st_size<64||
    (unsigned long long)st.st_size!=pin->size||(unsigned long long)st.st_size>268435456)fail("engine image metadata");
  int output=(int)syscall(SYS_memfd_create,"kelft-verified-engine",3);
  if(output<0)fail("engine sealed image");
  SHA sha=sha_init();char buffer[65536];
  for(;;){ssize_t n=read(input,buffer,sizeof buffer);if(n<0&&errno==EINTR)continue;if(n<0)fail("engine image read");if(!n)break;
    sha_update(&sha,buffer,(size_t)n);if(sha.bytes>pin->size)fail("engine image bound");
    size_t at=0;while(at<(size_t)n){ssize_t done=write(output,buffer+at,(size_t)n-at);if(done<0&&errno==EINTR)continue;if(done<=0)fail("engine image copy");at+=(size_t)done;}}
  unsigned long long size=sha.bytes;char actual[65];sha_end(&sha,actual);close(input);
  if(size!=pin->size||strcmp(actual,pin->sha256)||fcntl(output,F_ADD_SEALS,15)<0)fail("engine image changed");
  return output;
}
static int engine_worker(int argc,char **argv) {
  if(getuid()==0||geteuid()!=getuid())fail("engine worker identity");
  int tail=worker_grants(argc,argv,1);
  if(tail>=argc||strcmp(argv[tail],"/compiler"))fail("engine worker command");
  int seals=fcntl(3,F_GET_SEALS);
  if(syscall(SYS_close_range,3U,~0U,4)||seals<0||(seals&15)!=15||fcntl(3,F_SETFD,0))fail("engine descriptors");
  extern char **environ;execve("/compiler",argv+tail,environ);
  fail("engine handoff exec");return 125;
}
static int candidate_worker(int argc, char **argv) {
  if (argc < 2 || getuid() == 0 || geteuid() != getuid()) fail("candidate worker identity");
  int tail=worker_grants(argc,argv,0);
  int exec_error=-1;
  if(candidate_host_fd>=0){
    struct stat metadata;if(candidate_status_fd!=61||fstat(61,&metadata)||!S_ISREG(metadata.st_mode)||metadata.st_size!=0||prctl(PR_SET_DUMPABLE,0))fail("private process status");
    int errors[2];if(pipe2(errors,O_CLOEXEC))fail("process launch pipe");pid_t owner=getpid();pid_t child=fork();if(child<0)fail("process status guardian");
    if(child){
      close(errors[1]);close(candidate_host_fd);
      if(syscall(SYS_close_range,3U,~0U,4))fail("guardian descriptors");
      int status;while(waitpid(child,&status,0)<0){if(errno!=EINTR)fail("process status wait");}
      int error=0;ssize_t n;do{n=read(errors[0],&error,sizeof error);}while(n<0&&errno==EINTR);if(n<0||(n!=0&&n!=sizeof error))fail("process launch status");
      int report[2]={status,error};if(write(61,report,sizeof report)!=sizeof report)fail("process status publication");
      return WIFEXITED(status)?WEXITSTATUS(status):WIFSIGNALED(status)?128+WTERMSIG(status):125;
    }
    close(errors[0]);exec_error=errors[1];close(61);
    if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner)fail("process guardian changed");
  }
  int fd = open("/candidate", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || syscall(SYS_close_range,3U,~0U,4) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_DUMPABLE, 0)) fail("candidate worker preflight");
  if(candidate_host_fd>=0&&fcntl(candidate_host_fd,F_SETFD,0))fail("candidate host inheritance");
#define DENY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##n, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    #if defined(__x86_64__)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__aarch64__)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#else
#error Unsupported installed Linux architecture
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    DENY(clone), DENY(clone3),
#ifdef SYS_fork
    DENY(fork),
#endif
#ifdef SYS_vfork
    DENY(vfork),
#endif
    DENY(socket), DENY(socketpair), DENY(connect), DENY(bind), DENY(listen),
    DENY(accept), DENY(accept4), DENY(sendto), DENY(sendmsg), DENY(sendmmsg),
    DENY(unshare), DENY(setns), DENY(mount), DENY(umount2), DENY(pivot_root),
    DENY(ptrace), DENY(process_vm_readv), DENY(process_vm_writev),
    DENY(bpf), DENY(perf_event_open), DENY(keyctl), DENY(add_key), DENY(request_key),
    DENY(io_uring_setup), DENY(userfaultfd), DENY(execve),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
#undef DENY
  struct sock_fprog program = {(unsigned short)(sizeof filter / sizeof *filter), filter};
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) fail("candidate syscall boundary");
  argv[tail-1] = "/candidate";
  extern char **environ;
  syscall(SYS_execveat, fd, "", argv + tail - 1, environ, AT_EMPTY_PATH);
  if(exec_error>=0){int error=errno;ssize_t ignored=write(exec_error,&error,sizeof error);(void)ignored;}
  fail("candidate exec"); return 125;
}
static int candidate_run(int argc, char **argv) {
  int host_root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(host_root<0)fail("candidate host boundary");check_host(host_root);
  const char *project_arg = NULL, *policy = NULL, *wanted = NULL, *result_path = NULL, *cwd="/project";
  char *environment[32];unsigned environment_count=0;
  const char *roots[128]; int writes[128]; unsigned root_count = 0; int tail = argc;
  for (int n = 3; n < argc; n += 2) {
    if (!strcmp(argv[n], "--")) { tail = n + 1; break; }
    if (n + 1 >= argc) fail("candidate option value");
    if (!strcmp(argv[n], "--read") || !strcmp(argv[n], "--write")) {
      if (root_count >= 128) fail("candidate mount count");
      roots[root_count] = argv[n+1]; writes[root_count++] = !strcmp(argv[n], "--write");
    } else if (!strcmp(argv[n], "--project-root")) { if(project_arg) fail("duplicate candidate project"); project_arg=argv[n+1]; }
    else if (!strcmp(argv[n],"--host-fd")) {if(candidate_host_fd>=0||strcmp(argv[n+1],"63"))fail("candidate host descriptor");candidate_host_fd=63;struct stat socket;if(fstat(63,&socket)||!S_ISSOCK(socket.st_mode))fail("candidate host socket");}
    else if (!strcmp(argv[n],"--stdin-fd")) {if(candidate_input_fd>=0||strcmp(argv[n+1],"62"))fail("candidate stdin descriptor");candidate_input_fd=62;struct stat input;int seals=fcntl(62,F_GET_SEALS);if(fstat(62,&input)||!S_ISREG(input.st_mode)||input.st_size>65536||seals<0||(seals&15)!=15||lseek(62,0,SEEK_SET)<0)fail("candidate sealed input");}
    else if (!strcmp(argv[n],"--cwd")) {cwd=argv[n+1];if(!grant_contains("/project",cwd)||strstr(cwd,"/../")||strstr(cwd,"/./")||strstr(cwd,"//")||strchr(cwd,'\\')||strchr(cwd,':'))fail("candidate working directory");}
    else if (!strcmp(argv[n],"--environment")) {if(environment_count>=32)fail("candidate environment bound");char *key=argv[n+1],*equals=strchr(key,'=');if(!equals||equals==key||strlen(equals+1)>4096||(size_t)(equals-key)>128)fail("candidate environment");*equals=0;char upper[129];for(size_t j=0;j<=(size_t)(equals-key);j++)upper[j]=(key[j]>='a'&&key[j]<='z')?key[j]-32:key[j];if(!strncmp(upper,"KELFT_",6)||!strcmp(upper,"LD_PRELOAD")||!strcmp(upper,"LD_LIBRARY_PATH")||!strcmp(upper,"DYLD_INSERT_LIBRARIES")||!strcmp(upper,"DYLD_LIBRARY_PATH"))fail("candidate environment authority");for(unsigned j=0;j<environment_count;j++)if(!strcasecmp(environment[j],key))fail("candidate environment duplicate");for(char *p=key;*p;p++)if(!((*p>='A'&&*p<='Z')||(*p>='a'&&*p<='z')||*p=='_'||(p>key&&*p>='0'&&*p<='9')))fail("candidate environment key");environment[environment_count++]=key;}
    else if (!strcmp(argv[n], "--policy")) { if(policy) fail("duplicate candidate policy"); policy=argv[n+1]; }
    else if (!strcmp(argv[n], "--artifact-hash")) { if(wanted) fail("duplicate candidate hash"); wanted=argv[n+1]; }
    else if (!strcmp(argv[n], "--result")) { if(result_path) fail("duplicate candidate result"); result_path=argv[n+1]; }
    else if (!strcmp(argv[n], "--timeout-ms")) { supervision_timeout=candidate_number(argv[n+1],3600000); if(!supervision_timeout) fail("zero candidate timeout"); }
    else if (!strcmp(argv[n], "--memory-bytes")) { supervision_memory=candidate_number(argv[n+1],1073741824); if(!supervision_memory) fail("zero candidate memory"); }
    else if (!strcmp(argv[n], "--stdout-bytes")) supervision_stdout=candidate_number(argv[n+1],67108864);
    else if (!strcmp(argv[n], "--stderr-bytes")) supervision_stderr=candidate_number(argv[n+1],67108864);
    else fail("unknown candidate option");
  }
  if(!project_arg || !policy || !wanted || !result_path || strlen(policy)>1048576 ||
      strlen(wanted)!=71 || strncmp(wanted,"sha256:",7)) fail("candidate invocation");
  for(unsigned n=7;n<71;n++)if(!((wanted[n]>='0'&&wanted[n]<='9')||(wanted[n]>='a'&&wanted[n]<='f')))fail("candidate hash");
  supervision_combined=supervision_stdout+supervision_stderr;
  char project[PATH_MAX], candidate[PATH_MAX], worker[PATH_MAX];
  if(!realpath(project_arg,project)||!strcmp(project,"/"))fail("candidate project root");
  int artifact_parent=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC), project_fd=open(project,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(artifact_parent<0||project_fd<0||!realpath(argv[2],candidate))fail("candidate roots");
  strcpy(scratch,"/tmp/kelft-standalone-XXXXXX");if(!mkdtemp(scratch)||atexit(cleanup))fail("candidate snapshot");
  int destination=open(scratch,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  struct stat st;if(destination<0||lstat(candidate,&st)||!S_ISREG(st.st_mode)||st.st_size<64||st.st_size>67108864)fail("candidate executable");
  PinnedFile pin={candidate+1,wanted+7,(unsigned long long)st.st_size,(unsigned)st.st_mode&0777};
  measured(artifact_parent,&pin,destination);close(artifact_parent);
  char snapshot_candidate[PATH_MAX];if(snprintf(snapshot_candidate,sizeof snapshot_candidate,"%s/%s",scratch,candidate+1)>=(int)sizeof snapshot_candidate)fail("candidate snapshot path");
  snapshot_worker(worker);close(destination);
  if(candidate_host_fd>=0){int status=(int)syscall(SYS_memfd_create,"kelft-private-process-status",3);if(status<0)fail("process status allocation");if(status!=61){if(dup3(status,61,O_CLOEXEC)<0)fail("process status reservation");close(status);}candidate_status_fd=61;}
  char *arguments[1408],sources[128][64],guests[128][PATH_MAX];unsigned count=0;
#define CARG(s) do {if(count>=1407)fail("candidate argument bound");arguments[count++]=(char*)(s);}while(0)
  CARG(BWRAP_PATH);CARG("--unshare-user");CARG("--unshare-pid");CARG("--unshare-net");CARG("--unshare-ipc");CARG("--unshare-uts");CARG("--die-with-parent");CARG("--new-session");CARG("--tmpfs");CARG("/");CARG("--dir");CARG("/project");
  for(unsigned n=0;n<root_count;n++){
    char guest[PATH_MAX],leaf[NAME_MAX+1],actual[PATH_MAX];int fd;
    if(!realpath(roots[n],actual))fail("candidate grant missing");
    if(grant_contains(actual,"/tmp"))fail("candidate grant overlaps private temporary state");
    if(!strcmp(actual,project)){strcpy(guest,"/project");fd=openat(project_fd,".",O_PATH|O_NOFOLLOW|O_CLOEXEC);}
    else {beneath(project,actual,guest);int parent=parent_at(project_fd,guest+9,0,leaf);fd=openat(parent,leaf,O_PATH|O_NOFOLLOW|O_CLOEXEC);close(parent);}
    if(fd<0||fstat(fd,&st)||!S_ISDIR(st.st_mode))fail("candidate grant must be a native directory");
    inherited_mounts[inherited_mount_count++]=fd;
    if(snprintf(sources[n],sizeof sources[n],"/proc/self/fd/%d",fd)>=(int)sizeof sources[n])fail("candidate descriptor path");
    strcpy(guests[n],guest);
    CARG(writes[n]?"--bind":"--ro-bind");CARG(sources[n]);CARG(guests[n]);
  }
  close(project_fd);
  CARG("--ro-bind");CARG(snapshot_candidate);CARG("/candidate");CARG("--ro-bind");CARG(worker);CARG("/worker");CARG("--proc");CARG("/proc");CARG("--dev");CARG("/dev");if(strcmp(cwd,"/project")){int mapped=0;for(unsigned n=0;n<root_count;n++)if(grant_contains(guests[n],cwd))mapped=1;if(!mapped){CARG("--dir");CARG(cwd);}}CARG("--chdir");CARG(cwd);CARG("--clearenv");for(unsigned n=0;n<environment_count;n++){CARG("--setenv");CARG(environment[n]);CARG(environment[n]+strlen(environment[n])+1);}if(candidate_host_fd>=0){CARG("--setenv");CARG("KELFT_FS_REQUEST");CARG("63");CARG("--setenv");CARG("KELFT_FS_RESPONSE");CARG("63");CARG("--setenv");CARG("KELFT_FS_CWD");CARG(cwd);}CARG("--setenv");CARG("KELFT_CAPABILITIES");CARG(policy);CARG("--");CARG("/worker");CARG("--candidate-worker");if(candidate_host_fd>=0){CARG("--host-fd");CARG("63");CARG("--status-fd");CARG("61");}for(unsigned n=0;n<root_count;n++){CARG(writes[n]?"--write":"--read");CARG(guests[n]);}CARG("--");for(int n=tail;n<argc;n++)CARG(argv[n]);arguments[count]=NULL;
#undef CARG
  int code=supervise(arguments);int launch_error=0;
  if(candidate_status_fd>=0){int report[2];ssize_t n=pread(candidate_status_fd,report,sizeof report,0);if(n==sizeof report){candidate_signal=WIFSIGNALED(report[0])?WTERMSIG(report[0]):0;launch_error=report[1];if(!supervision_failure&&candidate_signal)supervision_failure=128+candidate_signal;}else if(!supervision_failure){supervision_failure=125;launch_error=EIO;}close(candidate_status_fd);}
  check_host(host_root);close(host_root);for(unsigned n=0;n<inherited_mount_count;n++)close(inherited_mounts[n]);
  int result=open(result_path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(result<0)fail("private candidate result");
  char outcome[192];int bytes=snprintf(outcome,sizeof outcome,"{\"exit\":%d,\"boundaryFailure\":%d,\"signal\":%d,\"launchError\":%d}\n",code,supervision_failure,candidate_signal,launch_error);
  if(bytes<0||write(result,outcome,(size_t)bytes)!=bytes||close(result))fail("candidate result publication");
  return code;
}

#ifdef KELFT_LINUX_WINDOWS_CROSS_SHA256
#include <strings.h>
/* Optional Linux x64 -> Windows x64 linker mechanism. Compiler and linker
 * execute sequentially in disjoint namespaces. No caller supplies tool paths,
 * libraries, response files, linker flags or a shell command. */
#include "cross-formats.h"
static unsigned char *cross_read(int root,const char *name,size_t *size) {
 char leaf[NAME_MAX+1];int parent=parent_at(root,name,0,leaf);
 int fd=openat(parent,leaf,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);close(parent);
 struct stat st;if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<0||st.st_size>67108864)fail("invalid cross-link file");
 *size=(size_t)st.st_size;unsigned char *b=malloc(*size?*size:1);if(!b)fail("cross-link allocation");
 size_t at=0;while(at<*size){ssize_t n=read(fd,b+at,*size-at);if(n<0&&errno==EINTR)continue;if(n<=0)fail("cross-link file read");at+=(size_t)n;}
 unsigned char extra;if(read(fd,&extra,1)!=0)fail("cross-link file grew");close(fd);return b;
}
static void cross_hash(const unsigned char *b,size_t size,char out[65]){SHA s=sha_init();sha_update(&s,b,size);sha_end(&s,out);}
static const char cross_prefix[]="cross/windows-x86_64/";
static int cross_output_parent=-1;
static char cross_output_leaf[NAME_MAX+1];
static void cross_directory(const char *suffix,char out[PATH_MAX]){
 if(snprintf(out,PATH_MAX,"%s/%s",scratch,suffix)>=PATH_MAX)fail("cross private path bound");
}
static void cross_publish(int parent,const char *name,const unsigned char *bytes,size_t size){
 int fd=openat(parent,name,O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
 struct stat st;if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1)fail("cross destination must be an unaliased regular file");
 if(ftruncate(fd,0))fail("cross output truncate");
 size_t at=0;while(at<size){if(stopped)exit(128+stopped);ssize_t n=write(fd,bytes+at,size-at);if(n<0&&errno==EINTR)continue;if(n<=0)fail("cross publication write");at+=(size_t)n;}
 if(fsync(fd)||close(fd))fail("cross publication close");
}
static int cross_link(void){
 char folder[PATH_MAX],rootfs[PATH_MAX],worker[PATH_MAX];
 cross_directory("cross-objects",folder);cross_directory("cross/windows-x86_64/rootfs",rootfs);
 int tool_root=open(rootfs,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(tool_root<0)fail("cross tool snapshot root");
 const char *mounts[]={"out","proc","dev"};for(unsigned n=0;n<3;n++)if(mkdirat(tool_root,mounts[n],0700)&&errno!=EEXIST)fail("cross tool mount point");
 close(tool_root);
 int objects=open(folder,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);size_t size;unsigned char *bytes=cross_read(objects,"target.obj",&size);cross_object(bytes,size);char object_hash[65];cross_hash(bytes,size,object_hash);
 /* Bind the validated, retained object inode, never a second resolution of
  * a caller-controlled project path. The compiler has already terminated. */
 int object=(int)syscall(SYS_memfd_create,"kelft-cross-object",3);if(object<0)fail("cross object snapshot");close(objects);
 size_t written=0;while(written<size){ssize_t n=write(object,bytes+written,size-written);if(n<0&&errno==EINTR)continue;if(n<=0)fail("cross object snapshot write");written+=(size_t)n;}free(bytes);
 if(fcntl(object,F_ADD_SEALS,15)<0||lseek(object,0,SEEK_SET)<0)fail("cross object seals");
 inherited_mount_count=0;inherited_mounts[inherited_mount_count++]=object;
 char descriptor[32];if(snprintf(descriptor,sizeof descriptor,"%d",object)>=(int)sizeof descriptor)fail("cross descriptor bound");
 snapshot_worker(worker);
 char private_output[PATH_MAX];cross_directory("cross-output",private_output);if(mkdir(private_output,0700))fail("cross private output");
 char *a[128];unsigned at=0;
#define X(s) do{if(at>=127)fail("cross linker argument bound");a[at++]=(char*)(s);}while(0)
 X(BWRAP_PATH);X("--unshare-user");X("--unshare-pid");X("--unshare-net");X("--unshare-ipc");X("--unshare-uts");X("--die-with-parent");X("--new-session");
 X("--ro-bind");X(rootfs);X("/");X("--ro-bind");X(worker);X("/worker");X("--ro-bind-data");X(descriptor);X("/input.obj");X("--bind");X(private_output);X("/out");X("--proc");X("/proc");X("--dev");X("/dev");X("--chdir");X("/out");X("--clearenv");X("--setenv");X("LC_ALL");X("C");X("--setenv");X("LD_LIBRARY_PATH");X("/lib");X("--");
 X("/worker");X("--candidate-worker");X("--read");X("/lib");X("--read");X("/lib64");X("--read");X("/sdk");X("--read");X("/input.obj");X("--read");X("/out");X("--write");X("/out");X("--");
 /* candidate_worker supplies /candidate as argv[0]. This executable is the
  * pinned Linux-native LLD, not a Windows artifact or a generic program path. */
 X("-flavor");X("link");X("/nologo");X("/machine:x64");X("/subsystem:console");X("/entry:k_start");X("/nodefaultlib");X("/Brepro");X("/timestamp:0");X("/threads:1");X("/stack:16777216,65536");X("/nxcompat");X("/dynamicbase");X("/dependentloadflag:0x800");X("/debug:none");X("/manifest:no");X("/out:/out/program.exe");X("/input.obj");X("/sdk/kernel32.lib");X("/sdk/shell32.lib");X("/sdk/ntdll.lib");a[at]=NULL;
#undef X
 supervision_stdout=supervision_stderr=supervision_combined=1048576;int result=supervise(a);close(object);inherited_mount_count=0;
 if(result)return result;
 int generated=open(private_output,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);bytes=cross_read(generated,"program.exe",&size);close(generated);cross_image(bytes,size);char image_hash[65];cross_hash(bytes,size,image_hash);
 cross_publish(cross_output_parent,cross_output_leaf,bytes,size);close(cross_output_parent);free(bytes);
 printf("{\"schema\":\"kelft.cross-build/1\",\"host\":\"linux-x86_64\",\"target\":\"windows-x86_64\",\"linkerProfile\":\"lld-coff/1\",\"profileSHA256\":\"%s\",\"objectSHA256\":\"sha256:%s\",\"executableSHA256\":\"sha256:%s\",\"nativeCertified\":false}\n",KELFT_LINUX_WINDOWS_CROSS_SHA256,object_hash,image_hash);return 0;
}
#endif

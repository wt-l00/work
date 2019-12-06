#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/telnet.h>
#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

#ifndef seccomp
int seccomp(unsigned int op, unsigned int flags, void *args)
{
    errno = 0;
    return syscall(__NR_seccomp, op, flags, args);
}
#endif
#define ARCH_NR AUDIT_ARCH_X86_64
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#define VALIDATE_ARCHITECTURE \
     BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), \
     BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
     BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
     BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define ALLOW_SYSCALL(name) \
     BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
     BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
 
#define KILL_SYSCALL(name) \
     BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
     BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define ALLOW_PROCESS \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)


struct sock_filter filter[] = {
    VALIDATE_ARCHITECTURE,
    EXAMINE_SYSCALL,
    KILL_SYSCALL(mkdir),
    KILL_SYSCALL(rmdir),
    ALLOW_PROCESS
};

struct sock_fprog prog = {
    .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
};

int main() {
  pid_t pid = fork();
  
  switch (pid) {
    case -1: /* error */
      exit(EXIT_FAILURE);
      
    case 0: /* child */
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
	      perror("prctl");
	      exit(EXIT_FAILURE);
      }

      //if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)){
      if(seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)){
	      perror("seccomp");
      }
      execl("/bin/bash", "/bin/bash", NULL);
      break;
    
    default: /* parent */ 
      wait(NULL); 
      break;
  }
  return 0;
}


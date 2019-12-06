
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

#define VALIDATE_ARCHITECTURE BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define ALLOW_SYSCALL(name) BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1),  BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
 
#define KILL_SYSCALL(name) BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define ALLOW_PROCESS BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)


struct sock_filter filter[] = {
    VALIDATE_ARCHITECTURE,
    EXAMINE_SYSCALL,
    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(write),
    ALLOW_SYSCALL(mprotect),
    ALLOW_SYSCALL(getuid),
    ALLOW_SYSCALL(getgid),
    ALLOW_SYSCALL(geteuid),
    ALLOW_SYSCALL(getegid),
    ALLOW_SYSCALL(setpgid),
    ALLOW_SYSCALL(munmap),
    ALLOW_SYSCALL(getppid),
    ALLOW_SYSCALL(getpgrp),
    ALLOW_SYSCALL(brk),
    ALLOW_SYSCALL(rt_sigaction),
    ALLOW_SYSCALL(statfs),
    ALLOW_SYSCALL(rt_sigprocmask),
    ALLOW_SYSCALL(rt_sigreturn),
    ALLOW_SYSCALL(arch_prctl),
    ALLOW_SYSCALL(ioctl),
    ALLOW_SYSCALL(access),
    ALLOW_SYSCALL(getdents64),
    ALLOW_SYSCALL(set_tid_address),
    ALLOW_SYSCALL(pipe),
    ALLOW_SYSCALL(select),
    ALLOW_SYSCALL(exit_group),
    ALLOW_SYSCALL(openat),
    ALLOW_SYSCALL(faccessat),
    ALLOW_SYSCALL(pselect6),
    ALLOW_SYSCALL(set_robust_list),
    ALLOW_SYSCALL(close),
    ALLOW_SYSCALL(prlimit64),
    ALLOW_SYSCALL(dup),
    ALLOW_SYSCALL(dup2),
    ALLOW_SYSCALL(getpid),
    ALLOW_SYSCALL(stat),
    ALLOW_SYSCALL(socket),
    ALLOW_SYSCALL(connect),
    ALLOW_SYSCALL(fstat),
    ALLOW_SYSCALL(clone),
    ALLOW_SYSCALL(execve),
    ALLOW_SYSCALL(lstat),
    ALLOW_SYSCALL(wait4),
    ALLOW_SYSCALL(uname),
    ALLOW_SYSCALL(fcntl),
    ALLOW_SYSCALL(lseek),
    ALLOW_SYSCALL(chdir),
    ALLOW_SYSCALL(mkdir),
    ALLOW_SYSCALL(mmap),
    ALLOW_SYSCALL(chown),
    ALLOW_SYSCALL(sysinfo),

    KILL_PROCESS
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

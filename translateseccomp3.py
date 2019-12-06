#! /usr/bin/python3
# coding: UTF-8
syscalllist = [
"read",
"write",
"open",
"close",
"stat",
"fstat",
"lstat",
"poll",
"lseek",
"mmap",
"mprotect",
"munmap",
"brk",
"rt_sigaction",
"rt_sigprocmask",
"rt_sigreturn",
"ioctl",
"pread64",
"pwrite64",
"readv",
"writev",
"access",
"pipe",
"select",
"sched_yield",
"mremap",
"msync",
"mincore",
"madvise",
"shmget",
"shmat",
"shmctl",
"dup",
"dup2",
"pause",
"nanosleep",
"getitimer",
"alarm",
"setitimer",
"getpid",
"sendfile",
"socket",
"connect",
"accept",
"sendto",
"recvfrom",
"sendmsg",
"recvmsg",
"shutdown",
"bind",
"listen",
"getsockname",
"getpeername",
"socketpair",
"setsockopt",
"getsockopt",
"clone",
"fork",
"vfork",
"execve",
"exit",
"wait4",
"kill",
"uname",
"semget",
"semop",
"semctl",
"shmdt",
"msgget",
"msgsnd",
"msgrcv",
"msgctl",
"fcntl",
"flock",
"fsync",
"fdatasync",
"truncate",
"ftruncate",
"getdents",
"getcwd",
"chdir",
"fchdir",
"rename",
"mkdir",
"rmdir",
"creat",
"link",
"unlink",
"symlink",
"readlink",
"chmod",
"fchmod",
"chown",
"fchown",
"lchown",
"umask",
"gettimeofday",
"getrlimit",
"getrusage",
"sysinfo",
"times",
"ptrace",
"getuid",
"syslog",
"getgid",
"setuid",
"setgid",
"geteuid",
"getegid",
"setpgid",
"getppid",
"getpgrp",
"setsid",
"setreuid",
"setregid",
"getgroups",
"setgroups",
"setresuid",
"getresuid",
"setresgid",
"getresgid",
"getpgid",
"setfsuid",
"setfsgid",
"getsid",
"capget",
"capset",
"rt_sigpending",
"rt_sigtimedwait",
"rt_sigqueueinfo",
"rt_sigsuspend",
"sigaltstack",
"utime",
"mknod",
"uselib",
"personality",
"ustat",
"statfs",
"fstatfs",
"sysfs",
"getpriority",
"setpriority",
"sched_setparam",
"sched_getparam",
"sched_setscheduler",
"sched_getscheduler",
"sched_get_priority_max",
"sched_get_priority_min",
"sched_rr_get_interval",
"mlock",
"munlock",
"mlockall",
"munlockall",
"vhangup",
"modify_ldt",
"pivot_root",
"_sysctl",
"prctl",
"arch_prctl",
"adjtimex",
"setrlimit",
"chroot",
"sync",
"acct",
"settimeofday",
"mount",
"umount2",
"swapon",
"swapoff",
"reboot",
"sethostname",
"setdomainname",
"iopl",
"ioperm",
"create_module",
"init_module",
"delete_module",
"get_kernel_syms",
"query_module",
"quotactl",
"nfsservctl",
"getpmsg",
"putpmsg",
"afs_syscall",
"tuxcall",
"security",
"gettid",
"readahead",
"setxattr",
"lsetxattr",
"fsetxattr",
"getxattr",
"lgetxattr",
"fgetxattr",
"listxattr",
"llistxattr",
"flistxattr",
"removexattr",
"lremovexattr",
"fremovexattr",
"tkill",
"time",
"futex",
"sched_setaffinity",
"sched_getaffinity",
"set_thread_area",
"io_setup",
"io_destroy",
"io_getevents",
"io_submit",
"io_cancel",
"get_thread_area",
"lookup_dcookie",
"epoll_create",
"epoll_ctl_old",
"epoll_wait_old",
"remap_file_pages",
"getdents64",
"set_tid_address",
"restart_syscall",
"semtimedop",
"fadvise64",
"timer_create",
"timer_settime",
"timer_gettime",
"timer_getoverrun",
"timer_delete",
"clock_settime",
"clock_gettime",
"clock_getres",
"clock_nanosleep",
"exit_group",
"epoll_wait",
"epoll_ctl",
"tgkill",
"utimes",
"vserver",
"mbind",
"set_mempolicy",
"get_mempolicy",
"mq_open",
"mq_unlink",
"mq_timedsend",
"mq_timedreceive",
"mq_notify",
"mq_getsetattr",
"kexec_load",
"waitid",
"add_key",
"request_key",
"keyctl",
"ioprio_set",
"ioprio_get",
"inotify_init",
"inotify_add_watch",
"inotify_rm_watch",
"migrate_pages",
"openat",
"mkdirat",
"mknodat",
"fchownat",
"futimesat",
"newfstatat",
"unlinkat",
"renameat",
"linkat",
"symlinkat",
"readlinkat",
"fchmodat",
"faccessat",
"pselect6",
"ppoll",
"unshare",
"set_robust_list",
"get_robust_list",
"splice",
"tee",
"sync_file_range",
"vmsplice",
"move_pages",
"utimensat",
"epoll_pwait",
"signalfd",
"timerfd_create",
"eventfd",
"fallocate",
"timerfd_settime",
"timerfd_gettime",
"accept4",
"signalfd4",
"eventfd2",
"epoll_create1",
"dup3",
"pipe2",
"inotify_init1",
"preadv",
"pwritev",
"rt_tgsigqueueinfo",
"perf_event_open",
"recvmmsg",
"fanotify_init",
"fanotify_mark",
"prlimit64",
"name_to_handle_at",
"open_by_handle_at",
"clock_adjtime",
"syncfs",
"sendmmsg",
"setns",
"getcpu",
"process_vm_readv",
"process_vm_writev",
"kcmp",
"finit_module",
"sched_setattr",
"sched_getattr",
"renameat2",
"seccomp",
"getrandom",
"memfd_create",
"kexec_file_load",
"bpf",
"execveat",
"userfaultfd",
"membarrier",
"mlock2",
"copy_file_range",
"preadv2",
"pwritev2",
"pkey_mprotect",
"pkey_alloc",
"pkey_free",
"statx",
"io_pgetevents"
]

file = open('starttime.txt')
start_time = int(file.read())
file.close()

file = open('auditlog.txt')
file_data = file.read()
file.close()

set_syscall = set()

for line in file_data.split('\n'):
  for data in line.split(' '):
    if 'msg=audit' in data:
      log_time = int(data[10:20])
      if log_time < start_time:
        break
    if 'syscall=' in data:
      set_syscall.add(data[8:])

str1 = """
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
"""

str2 = """
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
"""

file = open('source.c', 'w')
file.write(str1)
for num in sorted(set_syscall):
  file.write("    ALLOW_SYSCALL(" + syscalllist[int(num)] + "),\n")
file.write(str2)
file.close()

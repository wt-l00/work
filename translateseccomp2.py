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
"poll_time64",
"lseek",
"mmap",
"mprotect",
"munmap",
"brk",
"rt_sigaction",
"rt_sigprocmask",
"rt_sigreturn",
"ioctl",
"pread",
"pwrite",
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
"nanosleep_time64",
"getitimer",
"alarm",
"setitimer",
"getpid",
"sendfile64",
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
"chown",
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
"rt_sigtimedwait_time64",
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
"sched_rr_get_interval_time64",
"mlock",
"munlock",
"mlockall",
"munlockall",
"vhangup",
"modify_ldt",
"pivotroot",
"sysctl",
"prctl",
"arch_prctl",
"adjtimex64",
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
"setxattr",
"fsetxattr",
"getxattr",
"getxattr",
"fgetxattr",
"listxattr",
"listxattr",
"flistxattr",
"removexattr",
"removexattr",
"fremovexattr",
"kill",
"time",
"futex_time64",
"sched_setaffinity",
"sched_getaffinity",
"set_thread_area",
"io_setup",
"io_destroy",
"io_getevents_time64",
"io_submit",
"io_cancel",
"get_thread_area",
"lookup_dcookie",
"epoll_create",
"printargs",
"printargs",
"remap_file_pages",
"getdents64",
"set_tid_address",
"restart_syscall",
"semtimedop_time64",
"fadvise64",
"timer_create",
"timer_settime64",
"timer_gettime64",
"timer_getoverrun",
"timer_delete",
"clock_settime64",
"clock_gettime64",
"clock_getres_time64",
"clock_nanosleep_time64",
"exit",
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
"mq_timedsend_time64",
"mq_timedreceive_time64",
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
"pselect6_time64",
"ppoll_time64",
"unshare",
"set_robust_list",
"get_robust_list",
"splice",
"tee",
"sync_file_range",
"vmsplice",
"move_pages",
"utimensat_time64",
"epoll_pwait",
"signalfd",
"timerfd_create",
"eventfd",
"fallocate",
"timerfd_settime64",
"timerfd_gettime64",
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
"recvmmsg_time64",
"fanotify_init",
"fanotify_mark",
"prlimit64",
"name_to_handle_at",
"open_by_handle_at",
"clock_adjtime64",
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
"io_pgetevents_time64"
]

file = open('starttime.txt');
start_time = int(file.read())

file = open('auditlog.txt')
file_data = file.read()

set_syscall = set()

for line in file_data.split('\n'):
  for data in line.split(' '):
    if 'msg=audit' in data:
      log_time = int(data[10:20])
      if log_time < start_time:
        break
    if 'syscall=' in data:
      set_syscall.add(data[8:])

for num in sorted(set_syscall):
  print(syscalllist[int(num)])

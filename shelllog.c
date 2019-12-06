#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <seccomp.h>

int main() {
  int rc = -1;
  scmp_filter_ctx ctx;
  FILE *fp;

  ctx = seccomp_init(SCMP_ACT_LOG);
  pid_t pid = fork();
  
  switch (pid) {
    case -1: /* error */
      exit(EXIT_FAILURE);
      
    case 0: /* child */
      rc = seccomp_load(ctx);
      if (rc < 0) goto out;
      if ((fp = fopen("starttime.txt", "w")) == NULL) {
        printf("file error\n");
        exit(1);
      }
      time_t t = time(NULL);
      fprintf(fp, "%ld", t);
      fclose(fp);
      execl("/bin/bash", "/bin/bash", NULL);
      break;
    
    default: /* parent */ 
      wait(NULL);
      execlp("./exseccomp.sh", "-a", NULL);
      break;
  }

out:
    seccomp_release(ctx);
    return -rc;
}


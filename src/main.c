#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int init_container();
int create_container();

int main() {
  /**
   * Namespaces to isolate,
   *    CLONE_NEWIPC  = create the process in a new IPC namespace
   *    CLONE_NEWNET  = isolate network devices from host
   *    CLONE_NEWNS   = isolate mountpoints namespace
   *    CLONE_NEWPID  = create the process in a new PID namespace
   *    CLONE_NEWUSER = executed in a new user namespace, isolate users
   *    CLONE_NEWUTS  = isolate hostname
   *    CLONE_NEWCGROUP = Create the process in a new cgroup namespace
   *
   **/
  int namespaces = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWIPC |
                   CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWCGROUP;

  pid_t p =
      clone(init_container, malloc(4096) + 4096, SIGCHLD | namespaces, NULL);
  if (p == -1) {
    perror("clone");
    exit(1);
  }

  waitpid(p, NULL, 0);

  return 0;
}

int init_container(void* args) {
  (void)args;
  create_container();
  return (0);
}

int create_container(void) {
  char* cmd[] = {"sh", NULL};

  // mount external FS to isolate
  chroot("/home/alpine-minirootfs-3.12.0-x86_64/");

  // cd intoit
  chdir("/");

  // mount proc
  mount("proc", "proc", "proc", 0, "");

  // execute the containerized shell
  execv("/bin/busybox", cmd);
  perror("exec");

  exit(EXIT_FAILURE);
}

#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int init_container();
int create_container();

// list of linux capabilities to drop
cap_t cap;
const int cap_list[] = {
    CAP_AUDIT_CONTROL,   CAP_AUDIT_READ,   CAP_AUDIT_WRITE, CAP_BLOCK_SUSPEND,
    CAP_DAC_READ_SEARCH, CAP_FSETID,       CAP_IPC_LOCK,    CAP_MAC_ADMIN,
    CAP_MAC_OVERRIDE,    CAP_MKNOD,        CAP_SETFCAP,     CAP_SYSLOG,
    CAP_SYS_ADMIN,       CAP_SYS_BOOT,     CAP_SYS_MODULE,  CAP_SYS_NICE,
    CAP_SYS_RAWIO,       CAP_SYS_RESOURCE, CAP_SYS_TIME,    CAP_WAKE_ALARM};

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

void drop_capabilities() {
  printf("dropping capabilities...\n");
  cap_t caps = cap_get_proc();
  size_t num_caps = sizeof(cap_list) / sizeof(*cap_list);
  cap_set_flag(caps, CAP_INHERITABLE, num_caps, cap_list, CAP_CLEAR);
  cap_set_proc(caps);
}

int create_container(void) {
  printf("creating container...\n");

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

int init_container() {
  drop_capabilities();
  create_container();
  return (0);
}

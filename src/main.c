#define _GNU_SOURCE

#define OPTSTR "inmpuUcQ:P:C:h"
#define USAGE_FMT \
    "%s [-Q path-to-qcow2-image (optional)]\n [-P path-to-mountpoint]\n [-C command-to-execute] [-h]\n \
[-i reate the process in a new IPC namespace] \n [-n isolate network devices from host ] \n [-m isolate mountpoints namespace]\n \
[-p create the process in a new PID namespace] \n [-u isolate hostname] \n [-U Create the process in a new cgroup namespace]\n"
#define DEFAULT_PROGNAME "container_example"

#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int init_container();
int create_container();
void usage(char* progname);
void drop_capabilities();
void prepare_image(char* qcow2, char* path);
void cleanup_image(char* path);

// global variables, set up by cmd line args
char* QCOW2;
char* PATH;
char* CMD;

const char* FSTYPES[] = { "ext4", "ext3", "xfs", "btrfs" };
int FSTYPES_NUM = sizeof(FSTYPES) / sizeof(const char*);

// list of linux capabilities to drop
cap_t cap;
const int cap_list[] = {
    CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE, CAP_BLOCK_SUSPEND,
    CAP_DAC_READ_SEARCH, CAP_FSETID, CAP_IPC_LOCK, CAP_MAC_ADMIN,
    CAP_MAC_OVERRIDE, CAP_MKNOD, CAP_SETFCAP, CAP_SYSLOG,
    CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_MODULE, CAP_SYS_NICE,
    CAP_SYS_RAWIO, CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_WAKE_ALARM
};

void usage(char* progname)
{
    fprintf(stderr, USAGE_FMT, progname ? progname : DEFAULT_PROGNAME);
    exit(1);
}

int main(int argc, char* argv[])
{

    // command line parsing
    int opt;
    int namespaces;

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
    while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
        printf("option: %c\n", opt);
        switch (opt) {
        case 'i':
            namespaces |= CLONE_NEWIPC;
            break;
        case 'n':
            namespaces |= CLONE_NEWNET;
            break;
        case 'm':
            namespaces |= CLONE_NEWNS;
            break;
        case 'p':
            namespaces |= CLONE_NEWPID;
            break;
        case 'u':
            namespaces |= CLONE_NEWUTS;
            break;
        case 'U':
            namespaces |= CLONE_NEWUSER;
            break;
        case 'c':
            namespaces |= CLONE_NEWCGROUP;
            break;
        case 'Q':
            QCOW2 = optarg;
            printf("qcow2 image: %s\n", QCOW2);
            break;
        case 'P':
            PATH = optarg;
            printf("path is: %s\n", PATH);
            break;
        case 'C':
            CMD = optarg;
            printf("command is: %s\n", CMD);
            break;
        case 'h':
        default:
            usage(basename(argv[0]));
            break;
        }
    }

    // in case we deal with qcow2 files, we need root.
    if (QCOW2 != NULL) {
        if (geteuid() != 0) {
            printf("Run as root please.\n");
            exit(1);
        }
    }

    // prepare qcow2 image with nbd to mount
    if (QCOW2 != NULL) {
        printf("preparing image for mounting...\n");
        prepare_image(QCOW2, PATH);
    }

    int child_pid = clone(init_container, malloc(4096) + 4096, SIGCHLD | namespaces, NULL);
    if (child_pid == -1) {
        perror("clone");
        exit(1);
    }

    // wait...
    waitpid(child_pid, NULL, 0);

    // when exiting a container, cleanup it.
    // cleanup qcow2 image mounting.
    if (QCOW2 != NULL) {
        printf("cleaning up...\n");
        cleanup_image(PATH);
    }
    return 0;
}

void drop_capabilities()
{
    cap_t caps = cap_get_proc();
    size_t num_caps = sizeof(cap_list) / sizeof(*cap_list);
    cap_set_flag(caps, CAP_INHERITABLE, num_caps, cap_list, CAP_CLEAR);
    cap_set_proc(caps);
}

void prepare_image(char* qcow2, char* path)
{

    printf("checking mount dir...\n");
    // check if path exists, if not, create it.
    DIR* dir = opendir(path);
    if (dir) {
        /* Directory exists. */
        closedir(dir);
    } else if (ENOENT == errno) {
        /* Directory does not exist. */
        mkdir(path, 0755);
    }

    system("modprobe nbd max_part=8");

    printf("nbd: mounting qcow2 to target dir...\n");
    char* ndb_command = "qemu-nbd --connect=/dev/nbd2 ";
    char* command = malloc(strlen(ndb_command) + strlen(qcow2) + 1);
    strcpy(command, ndb_command);
    strcat(command, qcow2);

    system(command);

    // wait for nbd to finish...
    sleep(1);

    // try mount for each supported filesystem
    for (int fstype = 0; fstype < FSTYPES_NUM; fstype++) {
        // if mount successfully, go ahead, else try another FSType
        if (mount("/dev/nbd2p1", path, FSTYPES[fstype], 0, "") == 0) {
            printf("detected filesystem %s...\n", FSTYPES[fstype]);
            break;
        }
        perror("mount");
        printf("failed to detect %s...\n", FSTYPES[fstype]);
    }
}

void cleanup_image(char* path)
{
    // slow down
    sleep(1);
    umount(path);

    // let system know we have umounted.
    sleep(1);
    system("qemu-nbd -d /dev/nbd2 ");
}

int create_container(char* path, char* cmd)
{
    char* command[] = { cmd, NULL };

    // mount external FS to isolate
    chroot(path);
    perror("chroot");

    // cd into root
    chdir("/");

    //
    mount("sys", "sys", "sys", 0, "");
    mount("proc", "proc", "proc", 0, "");

    // drop prefixed capabilities
    printf("dropping capabilities...\n");
    drop_capabilities();

    // execute the containerized shell
    execv("/bin/sh", command);
    perror("exec");

    return (0);
}

int init_container()
{
    // chroot into the container and execute the command
    printf("creating container...\n");
    create_container(PATH, CMD);

    return (0);
}

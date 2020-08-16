#define _GNU_SOURCE

#define OPTSTR "inmpuUcQ:P:C:v:h"
#define USAGE_FMT \
    "%s [-Q path-to-qcow2-image (optional)]\n [-P path-to-mountpoint]\n [-C command-to-execute] [-h]\n \
[-i reate the process in a new IPC namespace] \n \
[-n isolate network devices from host ] \n \
[-m isolate mountpoints namespace]\n \
[-p create the process in a new PID namespace] \n \
[-u isolate hostname] \n \
[-c Create the process in a new cgroup ]\n \
[-U create the process in a new USER namespace ]\n \
[-v mount_host:mount_container ]\n"
#define DEFAULT_PROGNAME "container_example"

#include <dirent.h>
#include <errno.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int init_container();
int create_container();
void gen_random(char* s, const int len);
void usage(char* progname);
void cleanup_image(char* path);
void cleanup_mountpoints();
void drop_capabilities();
void prepare_image(char* qcow2, char* path);
void setup_mountpoints();
void usage(char* progname);

// global variables, set up by cmd line args
char* QCOW2;
char* PATH;
char* CMD;

char HOSTNAME[10];

char* MODPROBE_NBD_MODULE = "modprobe nbd max_part=8";
char* NBD_CMD = "qemu-nbd --connect=/dev/nbd0";
char* NBD_DISCONNECT_CMD = "qemu-nbd -d /dev/nbd0";
char* NBD_PART = "/dev/nbd0p1";

// keep track of mountpoints
char** MOUNT_POINTS;
int MOUNT_POINTS_NUM = 0;

const char* FSTYPES[] = { "ext4", "ext3", "ext2", "xfs", "btrfs" };
int FSTYPES_NUM = sizeof(FSTYPES) / sizeof(const char*);

void usage(char* progname)
{
    fprintf(stderr, USAGE_FMT, progname ? progname : DEFAULT_PROGNAME);
    exit(1);
}

void gen_random(char* s, const int len)
{
    // declare our
    static const char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}

int main(int argc, char* argv[])
{

    time_t t;
    srand((unsigned)time(&t));
    // command line parsing
    int opt;
    int namespaces;

    // generate the random hostname for the current container
    gen_random(HOSTNAME, 10);

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
        case 'v':
            MOUNT_POINTS_NUM++;
            MOUNT_POINTS = (char**)realloc(MOUNT_POINTS, (MOUNT_POINTS_NUM) * sizeof(char*));
            MOUNT_POINTS[MOUNT_POINTS_NUM - 1] = optarg;
            printf("%s\n", optarg);
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

    setup_mountpoints();

    int child_pid = clone(init_container, malloc(4096) + 4096, SIGCHLD | namespaces, NULL);
    if (child_pid == -1) {
        perror("clone");
        exit(1);
    }

    // wait...
    waitpid(child_pid, NULL, 0);

    printf("\ncontainer terminated\n");

    cleanup_mountpoints();

    // when exiting a container, cleanup it.
    // cleanup qcow2 image mounting.
    if (QCOW2 != NULL) {
        printf("cleaning up...\n");
        cleanup_image(PATH);
    }

    free(MOUNT_POINTS);

    printf("Exiting...\n");
    return 0;
}

void drop_capabilities()
{
    printf("dropping capabilities...\n");
    // list of capabilities
    // we want to drop from child process.
    int drop_caps[] = {
        CAP_NET_BIND_SERVICE,
        CAP_SYS_ADMIN,
        CAP_SYS_CHROOT,
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_CHOWN,
        CAP_DAC_OVERRIDE,
        CAP_DAC_READ_SEARCH,
        CAP_FOWNER,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_IPC_OWNER,
        CAP_KILL,
        CAP_LEASE,
        CAP_LINUX_IMMUTABLE,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_NET_ADMIN,
        CAP_NET_BROADCAST,
        CAP_NET_RAW,
        CAP_SETFCAP,
        CAP_SETGID,
        CAP_SETPCAP,
        CAP_SETUID,
        CAP_SYSLOG,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_PACCT,
        CAP_SYS_PTRACE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_SYS_TTY_CONFIG,
        CAP_WAKE_ALARM
    };
    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);

    // dropping capabilities
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            return;
        }
    }

    // dropping inheritable capabilities
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
        || cap_set_proc(caps)) {
        if (caps)
            cap_free(caps);
        return;
    }
    cap_free(caps);
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

    system(MODPROBE_NBD_MODULE);

    printf("nbd: mounting qcow2 to target dir...\n");
    char command[strlen(NBD_CMD) + strlen(qcow2) + 1];
    sprintf(command, "%s %s", NBD_CMD, qcow2);
    system(command);

    // wait for nbd to finish...
    sleep(1);

    // try mount for each supported filesystem
    for (int fstype = 0; fstype < FSTYPES_NUM; fstype++) {
        // if mount successfully, go ahead, else try another FSType
        if (mount(NBD_PART, path, FSTYPES[fstype], MS_REC, "") == 0) {
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
    system(NBD_DISCONNECT_CMD);
}

int create_container(char* path, char* cmd)
{
    char* command[] = { cmd, NULL };

    // mount external FS to isolate
    chroot(path);
    perror("chroot");

    // cd into root
    chdir("/");

    // this is an exception of the setup_mountpoints,
    // we always want a separate proc, so it's implicit
    mount("proc", "proc", "proc", 0, "");

    sethostname(HOSTNAME, strlen(HOSTNAME));
    // drop prefixed capabilities
    printf("dropping capabilities...\n");
    drop_capabilities();

    // execute the containerized shell
    execv("/bin/sh", command);
    perror("exec");

    return (0);
}

void setup_mountpoints()
{

    printf("creating mountpoints...\n");
    int mount_idx;
    for (mount_idx = 0; mount_idx < MOUNT_POINTS_NUM; mount_idx++) {
        // reconstruct the mountpoint from external, this will be
        // the internal mountpoint, removed the first '/' char
        // and then concatenated to the mount_path of the rootfs
        char mount_token[strlen(MOUNT_POINTS[mount_idx])];
        strcpy(mount_token, MOUNT_POINTS[mount_idx]);
        char* external_path = strtok(mount_token, ":");
        // get second string in split
        char* internal_path = strtok(NULL, ":");
        printf("%s %s \n", external_path, internal_path);
        // reconstruct the external mountpoint
        char mount_point[strlen(PATH) + strlen(internal_path)];
        sprintf(mount_point, "%s%s", PATH, internal_path + 1);

        //bind mount it
        mount(external_path, mount_point, "", MS_BIND | MS_REC | MS_PRIVATE, NULL);
    }
}

void cleanup_mountpoints()
{
    printf("cleaning up mountpoints...\n");

    // this is an exception of the setup_mountpoints,
    // we always want a separate proc, so it's implicit
    char* proc = "proc";
    char proc_target[strlen(proc) + strlen(PATH) + 1];
    sprintf(proc_target, "%s%s", PATH, proc);
    umount(proc_target);

    int mount_idx;
    for (mount_idx = 0; mount_idx < MOUNT_POINTS_NUM; mount_idx++) {
        // reconstruct the mountpoint from external, this will be
        // the internal mountpoint, removed the first '/' char
        // and then concatenated to the mount_path of the rootfs
        char mount_token[strlen(MOUNT_POINTS[mount_idx])];
        strcpy(mount_token, MOUNT_POINTS[mount_idx]);
        char* internal_path = strtok(mount_token, ":");
        // get second string in split
        internal_path = strtok(NULL, ":");
        // reconstruct the external mountpoint
        char mount_point[strlen(PATH) + strlen(internal_path)];
        sprintf(mount_point, "%s%s", PATH, internal_path + 1);

        //unmount it
        umount(mount_point);
    }
}

int init_container()
{
    // chroot into the container and execute the command
    printf("creating container...\n");
    create_container(PATH, CMD);

    return (0);
}

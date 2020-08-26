#define _GNU_SOURCE

#define OPTSTR "sinmpuUcX:Y:Z:W:Q:P:C:S:v:h"
#define USAGE_FMT \
    "Usage: %s [OPTION]...\n \
[-Q/--qcow2 path-to-qcow2-image (optional)]\n [-P/--path path-to-mountpoint]\n [-C/--command command-to-execute] [-h/--help]\n \
[-i/--ipc reate the process in a new IPC namespace] \n \
[-n/--net isolate network devices from host ] \n \
[-m/--mounts isolate mountpoints namespace]\n \
[-p/--pid create the process in a new PID namespace] \n \
[-u/--uts isolate hostname] \n \
[-c/--cgroup Create the process in a new cgroup ]\n \
[-U/--user create the process in a new USER namespace ]\n \
[-v/--volume mount_host:mount_container ]\n \
[-s/--seccomp-enable restrict enabled syscalls to th minimum ]\n"
#define DEFAULT_PROGNAME "container_example"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/securebits.h>
#include <sched.h>
#include <seccomp.h>
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
void set_userns_mapping(int pid);

int MAX_STRING = 100;

// global variables, set up by cmd line args
char* QCOW2;
char* PATH;
char* CMD;
char* SECCOMP_WHITELIST;

char HOSTNAME[10];

char* MODPROBE_NBD_MODULE = "modprobe nbd max_part=8";
char* NBD_CMD = "qemu-nbd --connect=/dev/nbd0";
char* NBD_DISCONNECT_CMD = "qemu-nbd -d /dev/nbd0";
char* NBD_PART = "/dev/nbd0p1";

// keep track of mountpoints
char** MOUNT_POINTS;
int MOUNT_POINTS_NUM = 0;

int NEW_USER_NS = 0;
int SECCOMP_ENABLE = 0;

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
    // initialize random seed using now time.
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
    static struct option long_options[] = {
        { "cgroup", no_argument, NULL, 'c' },
        { "help", no_argument, NULL, 'h' },
        { "ipc", no_argument, NULL, 'i' },
        { "mounts", no_argument, NULL, 'm' },
        { "net", no_argument, NULL, 'n' },
        { "pid", no_argument, NULL, 'p' },
        { "user", no_argument, NULL, 'U' },
        { "uts", no_argument, NULL, 'u' },
        { "seccomp-enable", no_argument, NULL, 's' },
        { "seccomp-whitelist", no_argument, NULL, 'S' },
        { "volume", required_argument, NULL, 'v' },
        { "qcow2", required_argument, NULL, 'Q' },
        { "path", required_argument, NULL, 'P' },
        { "command", required_argument, NULL, 'C' },
        { NULL, 0, NULL, 0 }
    };
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, OPTSTR, long_options, &option_index)) != EOF) {
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
            NEW_USER_NS = 1;
            break;
        case 'c':
            namespaces |= CLONE_NEWCGROUP;
            break;
        case 'v':
            // populate the MOUNT_POINTS array with all the mountpoints in form of
            // host_dir:guest_dir
            MOUNT_POINTS_NUM++;
            MOUNT_POINTS = (char**)realloc(MOUNT_POINTS, (MOUNT_POINTS_NUM) * sizeof(char*));
            MOUNT_POINTS[MOUNT_POINTS_NUM - 1] = optarg;
            break;
        case 's':
            SECCOMP_ENABLE = 1;
            break;
        case 'S':
            SECCOMP_WHITELIST = optarg;
            break;
        case 'Q':
            QCOW2 = optarg;
            break;
        case 'P':
            PATH = optarg;
            break;
        case 'C':
            CMD = optarg;
            break;
        case 'h':
        default:
            usage(basename(argv[0]));
            break;
        }
    }

    // in case we deal with qcow2 files, we need root.
    if (QCOW2 != NULL || NEW_USER_NS == 0) {
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

    // actualize bindmounts
    setup_mountpoints();

    // we now clone the process with constrained namespaces.
    // init_container will initialize the container and capabilities
    int child_pid = clone(init_container, malloc(4096) + 4096, SIGCHLD | namespaces, NULL);
    if (child_pid == -1) {
        perror("clone");
        printf("1\n");
        exit(1);
    }

    // do user/group mapping only if we are
    // isolating user_ns
    if (NEW_USER_NS == 1) {
        set_userns_mapping(child_pid);
    }

    // wait...
    waitpid(child_pid, NULL, 0);

    printf("\ncontainer terminated\n");

    // remove bindmounts
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
    int drop_caps[] = { CAP_NET_BIND_SERVICE,
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
        CAP_WAKE_ALARM };
    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);

    // dropping capabilities
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            return;
        }
    }

    // dropping inheritable capabilities
    cap_t caps = NULL;
    if (!(caps = cap_get_proc()) || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR) || cap_set_proc(caps)) {
        if (caps)
            cap_free(caps);
        return;
    }
    cap_free(caps);

    // set securebits:
    //
    prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NO_SETUID_FIXUP | SECBIT_KEEP_CAPS | SECBIT_NO_CAP_AMBIENT_RAISE | SECURE_ALL_LOCKS);
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

    // we need the nbd module loaded to make qcow2 images to work.
    system(MODPROBE_NBD_MODULE);

    printf("nbd: mounting qcow2 to target dir...\n");
    // build our command using the passed qcow2 path
    char command[strlen(NBD_CMD) + strlen(qcow2) + 1];
    sprintf(command, "%s %s", NBD_CMD, qcow2);
    system(command);

    // wait for nbd to finish...
    sleep(1);

    // try mount for each supported filesystem
    for (int fstype = 0; fstype < FSTYPES_NUM; fstype++) {
        // if mount successfully, go ahead, else try another FSType
        if (mount(NBD_PART, path, FSTYPES[fstype], 0, "") == 0) {
            printf("detected filesystem %s...\n", FSTYPES[fstype]);
            break;
        }
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

/* to detect what syscall are necessary for the bare minimum container, set to
// SCMP_ACT_LOG then use
//          journalctl -f | grep -Eo 'syscall=[0-9]+ ' | cut -d'=' -f2 | sort -un
//  and whitelist those.
//
//  to see the name of the available syscalls in the system,
//          awk 'BEGIN { print "#include <sys/syscall.h>" } /p_syscall_meta/ { syscall = substr($NF, 19); printf "syscalls[SYS_%s] = \"%s\";\n", syscall, syscall }' \
//          /proc/kallsyms | sort -u | gcc -E -P -
*/
void seccomp_restrict()
{
    printf("restricting seccomp profile...\n");
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flistxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(llistxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fgetxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lgetxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getxattr), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fadvise64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setpgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statfs), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pselect6), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);

    char* seccomp_custom_rule = strtok(SECCOMP_WHITELIST, ",");
    while (seccomp_custom_rule != NULL) {
        printf("### %s %d\n", seccomp_custom_rule, atoi(seccomp_custom_rule));
        int rule = atoi(seccomp_custom_rule);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, rule, 0);

        // go to next string
        seccomp_custom_rule = strtok(NULL, ",");
    }
    seccomp_load(ctx);
}

int create_container(char* path, char* cmd)
{
    char* command[] = { cmd, NULL };

    // mount external FS to isolate
    chroot(path);

    // cd into root
    chdir("/");

    // this is an exception of the setup_mountpoints,
    // we always want a separate proc, so it's implicit
    mount("proc", "proc", "proc", 0, "");

    // set container hostname to random hostname
    sethostname(HOSTNAME, strlen(HOSTNAME));

    // drop prefixed capabilities
    drop_capabilities();

    if (SECCOMP_ENABLE == 1) {
        seccomp_restrict();
    }
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
        // reconstruct the external mountpoint
        char mount_point[strlen(PATH) + strlen(internal_path)];
        sprintf(mount_point, "%s%s", PATH, internal_path + 1);

        // bind mount it
        mount(external_path, mount_point, "", MS_BIND, NULL);
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

        // unmount it
        umount(mount_point);
    }
}

/**
 * map user process to root inside the container, this way
 * when we isolate the user namespace, we have root inside
 * the container mapped to the current non-root user outside
 * of it.
 */
void set_userns_mapping(int pid)
{
    char map_buf[MAX_STRING];

    // create the path to the uid_map
    char uid_path[MAX_STRING];
    snprintf(uid_path, MAX_STRING, "/proc/%ld/uid_map", (long)pid);

    // create the path to the gid_map
    char gid_path[MAX_STRING];
    snprintf(gid_path, MAX_STRING, "/proc/%ld/gid_map", (long)pid);

    // create the user mapping in the form of "0 UID 1"
    snprintf(map_buf, MAX_STRING, "0 %ld 1", (long)getuid());
    char* uid_map = map_buf;

    // create the group mapping in the form of "0 UID 1"
    snprintf(map_buf, MAX_STRING, "0 %ld 1", (long)getgid());
    char* gid_map = map_buf;

    // make the group map writable by putting "deny" inside
    // of the /proc/PID/setgroups file.
    char setgroups_path[MAX_STRING];
    char* setgroups_write = "deny";
    snprintf(setgroups_path, MAX_STRING, "/proc/%ld/setgroups", (long)pid);

    int fd;

    // setgroups write
    fd = open(setgroups_path, O_RDWR);
    if (fd == -1) {
        printf("Error opening file %s\n", setgroups_path);
    }
    write(fd, setgroups_write, strlen(setgroups_write));

    // gid_map write
    fd = open(gid_path, O_RDWR);
    if (fd == -1) {
        printf("Error opening file %s\n", gid_path);
    }
    write(fd, gid_map, strlen(gid_map));
    close(fd);

    // uid_map write
    fd = open(uid_path, O_RDWR);
    if (fd == -1) {
        printf("Error opening file %s\n", uid_path);
    }
    write(fd, uid_map, strlen(uid_map));
    close(fd);
}

int init_container()
{
    // chroot into the container and execute the command
    printf("creating container...\n");
    create_container(PATH, CMD);

    return (0);
}

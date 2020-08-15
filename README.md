# Simple linux container implementation in C

This is inspired by the Gontainer project by alegrey91, available here:

[Gontainer](https://github.com/alegrey91/Gontainer)

## To start

Download a rootfs that we will use for our container, this will be based on Alpine,
download it:

`http://dl-cdn.alpinelinux.org/alpine/v3.12/releases/x86_64/alpine-minirootfs-3.12.0-x86_64.tar.gz`

then unpack it in /home

```
sudo mkdir /home/alpine-minirootfs-3.12.0-x86_64; 
sudo chown 1000.1000 /home/alpine-minirootfs-3.12.0-x86_64
tar xfv alpine-minirootfs-3.12.0-x86_64.tar.gz -C /home/alpine-minirootfs-3.12.0-x86_64
```
### Compiling

`make clean`

### Executing

`./container_example`

you will enter a containerized environment based on **alpine linux**, with busybox

The following namespace isolation flags are passed to create the container:

   *    `CLONE_NEWIPC`    = create the process in a new IPC namespace
   *    `CLONE_NEWNET`    = isolate network devices from host
   *    `CLONE_NEWNS `    = isolate mountpoints namespace
   *    `CLONE_NEWPID`    = create the process in a new PID namespace
   *    `CLONE_NEWUSER`   = executed in a new user namespace, isolate users
   *    `CLONE_NEWUTS`    = isolate hostname
   *    `CLONE_NEWCGROUP` = Create the process in a new cgroup namespace




## References

1. https://medium.com/@teddyking/linux-namespaces-850489d3ccf
3. http://ifeanyi.co/posts/linux-namespaces-part-1/
4. https://klotzandrew.com/blog/container-from-scratch
6. https://en.wikipedia.org/wiki/Linux_namespaces

### Wishlist

In future it would be fun to implement:

- [x] complete cli interface much like `gontainer` does
- [x] qcow2 support, to use an existing VM as a template/rootfs for the container, much like `systemd-nspanw` does
- [ ] mountpoints support docker style `-v a:b -v c:d`
- [ ] img support to use existing VM as template/rootfs for the container
- [ ] directly use docker images as template/rootfs for the container
- [ ] lxc-like boot to have a full system instead of a single process

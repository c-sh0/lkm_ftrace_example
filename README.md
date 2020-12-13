# kernel_ftrace_example
Example ftrace LKM (Loadable Kernel Module)

## Description
This module will grant CAP_NET_BIND_SERVICE to any calls to `net/ipv4/af_inet.c:inet_bind()` allowing non-privileged users to biind() to privileged ports < 1024.

In `net/ipv4/af_inet.c:inet_bind()` there is a capabilities check to see if the calling process has `CAP_NET_BIND_SERVICE` capabilities if the requested port is considered privileged (< 1024).
```
    int __inet_bind() .....
    ...
    if (snum && snum < inet_prot_sock(net) &&
             !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
                  goto out;
```

 - Use the ftrace framework to grab the `inet_bind()` and insert our own function.
 - Our function grants `CAP_NET_BIND_SERVICE` to the process before calling the real `inet_bind()`
 - Tested on CentOS kernel-ml-5.6.15 (gcc (GCC) 9.3.1)

Note: Live patching has changed in newer kernels. The kallsyms_lookup_name() and kallsyms_on_each_symbol() functions are no longer exported
 * https://lwn.net/Articles/813350/
 * https://github.com/torvalds/linux/commit/0bd476e6c67190b5eb7b6e105c8db8ff61103281
 * https://github.com/torvalds/linux/tree/master/samples/livepatch

## Usage
- inet_bind_mod.c :- Kernel module
- bind_socket.c :- Simple bind() socket to a privileged port
```
# make clean && make
# insmod ./inet_bind_mod.ko
```

Run bind_socket as a normal user
```
# su - test01
$ ./bind_socket
uname:test01 uid:1000 gid:1000
bind() port:12 succeeded
ipaddr:0.0.0.0 port:12
exit
```

Check dmesg
```
$ dmesg
[ 5748.680458] EXAMPLE: kallsyms_walk_callback() found: inet_bind @addr: 0000000033a8f6c9
[ 5748.691148] EXAMPLE: init inet_bind() module: OK
[ 5771.177134] EXAMPLE: patched_function(): start
[ 5771.177482] EXAMPLE: task_name: bind_socket task_pid: 4987 task_vpid: 4987 task_tgid: 4987
[ 5771.177903] EXAMPLE: user_uid:1000 user_gid:1000 user_euid:1000 user_egid:1000
[ 5771.178426] EXAMPLE: CAP_NET_BIND_SERVICE, DENIED for this task, Changing permissions ...
[ 5771.178902] EXAMPLE: CAP_NET_BIND_SERVICE - OK
[ 5771.178902] EXAMPLE: patched_function(): calling real inet_bind()
```

Remove the module
```
# rmmod inet_bind_mod
```

## References
 1. [ftrace](https://www.kernel.org/doc/Documentation/trace/ftrace.txt) - Kernel Documentation
 2. [Credentials in Linux](https://www.kernel.org/doc/Documentation/security/credentials.txt) - Kernel Documentation
 3. [capabilities(7)](http://man7.org/linux/man-pages/man7/capabilities.7.html) - Man Page


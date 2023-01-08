# ectg

_eBPF Canarytoken trigger_.

CLI tool which triggers DNS based Canarytokens when `execve` syscalls are invoked for programs at specified paths.

### Requirements

- go 1.18/1.19
- Linux 4.9+
- clang-11/clang-14

### Build & Run

First, generate a DNS Canarytoken at `https://canarytokens.org/generate`.

Afterwards:
```shell
$ make generate
$ go build
$ sudo ./ectg -hostname 6j4n7c2flo71qa0r9g0simq2r.canarytokens.com -paths /usr/bin/whoami,/usr/bin/hostname
```

With `ectg` running, execute `whoami` in a separate shell session — the Canarytoken will trigger and an email will be sent to the address you entered when creating the token.

### References

- https://github.com/cilium/ebpf
- https://blog.thinkst.com/2020/06/canarytokens-org-quick-free-detection-for-the-masses-2.html
- https://ebpf.io/

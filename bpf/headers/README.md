
###  limux vmlinux.h
#### Generate the vmlinux.h for extracting the definition of every type in the current running kernel
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
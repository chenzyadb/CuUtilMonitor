# CuUtilMonitor
Use eBPF to monitor the kernel scheduler for CPU utilization.  

## Build  
Use Android NDK and AOSP source code to build this project.  
```
    clang \
    --target=bpf \
    -c \
    -nostdlibinc -no-canonical-prefixes -O2 \
    -isystem android/bionic/libc/include \
    -isystem android/bionic/libc/kernel/uapi \
    -isystem android/bionic/libc/kernel/uapi/asm-arm64 \
    -isystem android/bionic/libc/kernel/android/uapi \
    -I       android/system/core/libcutils/include \
    -I       android/system/bpf/progs/include \
    -MD -MF CuUtilMonitor.d -o CuUtilMonitor.o src/cu_util_monitor.c
```

## Credit  
[Android Open Source Project](https://source.android.google.cn/)

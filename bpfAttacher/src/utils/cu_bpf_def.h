#ifndef __CU_BPF_DEF__
#define __CU_BPF_DEF__ 1

#include <linux/bpf.h>
#include <stdint.h>
#include <stddef.h>

#define __UNUSED __attribute__((unused))

#define CU_INLINE __attribute__((always_inline)) inline

#define CU_SEC(name) __attribute__((section(name), used))

#define CU_LICENSE(name) const char _license[] CU_SEC("license") = (name)

#define CU_KERNEL_VERSION(major, minor, sub) (((major) << 24) + ((minor) << 16) + (sub))

static int (*bpf_map_set_elem)(const void* map, const void* key, const void* value, unsigned long long flags) 
= (int(*)(const void*, const void*, const void*, unsigned long long))BPF_FUNC_map_update_elem;

static void* (*bpf_map_get_elem)(const void* map, const void* key) 
= (void*(*)(const void*, const void*))BPF_FUNC_map_lookup_elem;

static int (*bpf_map_remove_elem)(const void* map, const void* key) 
= (int(*)(const void*, const void*))BPF_FUNC_map_delete_elem;

typedef struct {
    enum bpf_map_type type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
} cu_bpf_map_def;

#define CU_DEFINE_BPF_MAP(map_name, map_type, key_type, value_type, max_entries_num)                                  \
    const cu_bpf_map_def CU_SEC("bpf_map_" #map_name) map_name = {                                                     \
        .type = BPF_MAP_TYPE_##map_type,                                                                              \
        .key_size = sizeof(key_type),                                                                                 \
        .value_size = sizeof(value_type),                                                                             \
        .max_entries = (max_entries_num),                                                                             \
        .map_flags = 0                                                                                                \
    };                                                                                                                \
                                                                                                                      \
    static CU_INLINE __UNUSED int set_##map_name##_elem                                                              \
        (const key_type* key, const value_type* value, unsigned long long flags)                                      \
    {                                                                                                                 \
        return bpf_map_set_elem(&map_name, key, value, flags);                                                        \
    }                                                                                                                 \
                                                                                                                      \
    static CU_INLINE __UNUSED value_type* get_##map_name##_elem(const key_type* key)                                 \
    {                                                                                                                 \
        return bpf_map_get_elem(&map_name, key);                                                                      \
    }                                                                                                                 \
                                                                                                                      \
    static CU_INLINE __UNUSED int remove_##map_name##_elem(const key_type* key)                                      \
    {                                                                                                                 \
        return bpf_map_remove_elem(&map_name, key);                                                                   \
    }

#define CU_DEFINE_BPF_PROG(tracepoint_name, func_name) CU_SEC("bpf_prog_" tracepoint_name) int func_name

static unsigned long long (*bpf_ktime_get_ns)(void) = (unsigned long long(*)(void))BPF_FUNC_ktime_get_ns;

static unsigned long long (*bpf_get_current_pid_tgid)(void) = (unsigned long long(*)(void))BPF_FUNC_get_current_pid_tgid;

static unsigned long long (*bpf_get_current_uid_gid)(void) = (unsigned long long(*)(void))BPF_FUNC_get_current_uid_gid;

static unsigned long long (*bpf_get_smp_processor_id)(void) = (unsigned long long(*)(void))BPF_FUNC_get_smp_processor_id;

#endif

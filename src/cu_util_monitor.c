// CuUtilMonitor V1 by chenzyadb@github.com

#include "cu_bpf_def.h"

CU_DEFINE_BPF_MAP(last_sched_switch_ts_map, PERCPU_ARRAY, int, uint64_t, 1)
CU_DEFINE_BPF_MAP(cpu_util_idle_total_ns_map, ARRAY, int, uint64_t, 16)
CU_DEFINE_BPF_MAP(cpu_util_busy_total_ns_map, ARRAY, int, uint64_t, 16)

static CU_INLINE uint64_t get_last_sched_switch_ts(void)
{
    int key = 0;
    uint64_t* last_sched_switch_ts_addr = get_last_sched_switch_ts_map_elem(&key);
    if (last_sched_switch_ts_addr != NULL) {
        return *last_sched_switch_ts_addr;
    }
    return 0;
}

static CU_INLINE void set_last_sched_switch_ts(uint64_t value)
{
    int key = 0;
    set_last_sched_switch_ts_map_elem(&key, &value, BPF_ANY);
}

static CU_INLINE uint64_t get_cpu_util_idle_total_ns(int cpu)
{
    uint64_t* cpu_util_idle_total_ns_addr = get_cpu_util_idle_total_ns_map_elem(&cpu);
    if (cpu_util_idle_total_ns_addr != NULL) {
        return *cpu_util_idle_total_ns_addr;
    }
    return 0;
}

static CU_INLINE void set_cpu_util_idle_total_ns(int cpu, uint64_t value)
{
    set_cpu_util_idle_total_ns_map_elem(&cpu, &value, BPF_ANY);
}

static CU_INLINE uint64_t get_cpu_util_busy_total_ns(int cpu)
{
    uint64_t* cpu_util_busy_total_ns_addr = get_cpu_util_busy_total_ns_map_elem(&cpu);
    if (cpu_util_busy_total_ns_addr != NULL) {
        return *cpu_util_busy_total_ns_addr;
    }
    return 0;
}

static CU_INLINE void set_cpu_util_busy_total_ns(int cpu, uint64_t value)
{
    set_cpu_util_busy_total_ns_map_elem(&cpu, &value, BPF_ANY);
}

struct sched_switch_args 
{
    unsigned long long pad;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

CU_DEFINE_BPF_PROG("tracepoint/sched/sched_switch", trace_sched_switch)(struct sched_switch_args* args) 
{
    if (args == NULL) {
        return 0;
    }

    int cpu = (int)bpf_get_smp_processor_id();
    uint64_t time = bpf_ktime_get_ns();

    uint64_t sched_switch_interval = time - get_last_sched_switch_ts();
    if (sched_switch_interval == 0) {
        return 0;
    }
    set_last_sched_switch_ts(time);

    if (args->prev_pid == 0) {
        uint64_t cpu_util_idle_total_ns = get_cpu_util_idle_total_ns(cpu) + sched_switch_interval;
        set_cpu_util_idle_total_ns(cpu, cpu_util_idle_total_ns);
    } else {
        uint64_t cpu_util_busy_total_ns = get_cpu_util_busy_total_ns(cpu) + sched_switch_interval;
        set_cpu_util_busy_total_ns(cpu, cpu_util_busy_total_ns);
    }
    
    return 0;
}

CU_LICENSE("GPL");

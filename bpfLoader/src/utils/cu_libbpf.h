#pragma once

#include "libcu.h"
#include "CuFile.h"
#include "CuFormat.h"
#include "cu_bpf_def.h"
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/resource.h>

namespace CU 
{
    namespace Bpf
    {
        inline int CreateMap(
            bpf_map_type mapType,
            const std::string &name,
            uint32_t keySize,
            uint32_t valSize,
            uint32_t maxEntries,
            uint32_t mapFlags
        ) {
            if (name.length() >= BPF_OBJ_NAME_LEN) {
                return -1;
            }

            bpf_attr attr{};
            attr.map_type = mapType;
            attr.key_size = keySize;
            attr.value_size = valSize;
            attr.max_entries = maxEntries;
            attr.map_flags = mapFlags;
            std::strncpy(attr.map_name, name.data(), name.length());

            return static_cast<int>(syscall(__NR_bpf, BPF_MAP_CREATE, std::addressof(attr), sizeof(attr)));
        }

        inline int LoadProgram(
            bpf_prog_type progType,
            const std::string &name,
            const bpf_insn* bpfInsns,
            uint32_t progLen,
            const std::string &license
        ) {
            static const auto kernelVersion = []() -> uint32_t {
                auto kernelVersion = CU::ReadFile("/proc/version");
                if (CU::StrStartsWith(kernelVersion, "Linux version ")) {
                    auto version = CU::StrSplit(CU::SubPrevStr(CU::SubPostStr(kernelVersion, "Linux version "), '-'), '.');
                    if (version.size() == 3) {
                        uint32_t kver_major = CU::StrToInt(version[0]);
                        uint32_t kver_minor = CU::StrToInt(version[1]);
                        uint32_t kver_sub = CU::StrToInt(version[2]);
                        return CU_KERNEL_VERSION(kver_major, kver_minor, kver_sub);
                    }
                }
                return 0;
            };

            if (name.length() >= BPF_OBJ_NAME_LEN) {
                return -1;
            }

            auto insnCount = progLen / sizeof(bpf_insn);
            if (insnCount > BPF_MAXINSNS) {
                return -1;
            }

            bpf_attr attr{};
            attr.prog_type = progType;
            attr.kern_version = kernelVersion();
            attr.license = reinterpret_cast<uint64_t>(license.data());
            attr.insns = reinterpret_cast<uint64_t>(bpfInsns);
            attr.insn_cnt = insnCount;
            std::strncpy(attr.prog_name, name.data(), name.length());

            return static_cast<int>(syscall(__NR_bpf, BPF_PROG_LOAD, std::addressof(attr), sizeof(attr)));
        }

        inline int PinObject(int fd, const std::string &path)
        {
            bpf_attr attr{};
            attr.bpf_fd = static_cast<uint32_t>(fd);
            attr.pathname = reinterpret_cast<uint64_t>(path.data());
            return static_cast<int>(syscall(__NR_bpf, BPF_OBJ_PIN, std::addressof(attr), sizeof(attr)));
        }

        inline int OpenObject(const std::string &path)
        {
            bpf_attr attr{};
            attr.pathname = reinterpret_cast<uint64_t>(path.data());
            return static_cast<int>(syscall(__NR_bpf, BPF_OBJ_GET, std::addressof(attr), sizeof(attr)));
        }

        inline int ProgAttachTracePoint(int progFd, const std::string &tracePoint)
        {
            perf_event_attr perfEventAttr{};
            perfEventAttr.config = CU::StrToULong(CU::ReadFile(CU::Format("/sys/kernel/tracing/events/{}/id", tracePoint)));
            perfEventAttr.type = PERF_TYPE_TRACEPOINT;
            perfEventAttr.sample_period = 1;
            perfEventAttr.wakeup_events = 1;
            int targetFd = syscall(__NR_perf_event_open, std::addressof(perfEventAttr), -1, 0, -1, 0);
            if (targetFd < 0) {
                return -1;
            }
            if (ioctl(targetFd, PERF_EVENT_IOC_SET_BPF, progFd) < 0) {
                return -1;
            }
            if (ioctl(targetFd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
                return -1;
            }
            return targetFd;
        }

        template <typename _Key_Ty, typename _Val_Ty>
        inline _Val_Ty GetElementValue(int fd, _Key_Ty key, _Val_Ty defaultValue)
        {
            auto elemValue = defaultValue;
            bpf_attr attr{};
            attr.map_fd = static_cast<uint32_t>(fd);
            attr.key = reinterpret_cast<uint64_t>(std::addressof(key));
            attr.value = reinterpret_cast<uint64_t>(std::addressof(elemValue));
            syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, std::addressof(attr), sizeof(attr));
            return elemValue;
        }

        template <typename _Key_Ty, typename _Val_Ty>
        inline int SetElementValue(int fd, _Key_Ty key, _Val_Ty value, uint64_t flags)
        {
            bpf_attr attr{};
            attr.map_fd = static_cast<uint32_t>(fd);
            attr.key = reinterpret_cast<uint64_t>(std::addressof(key));
            attr.value = reinterpret_cast<uint64_t>(std::addressof(value));
            attr.flags = flags;
            return static_cast<int>(syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, std::addressof(attr), sizeof(attr)));
        }

        template <typename _Key_Ty>
        inline int DeleteElement(int fd, _Key_Ty key)
        {
            bpf_attr attr{};
            attr.map_fd = static_cast<uint32_t>(fd);
            attr.key = reinterpret_cast<uint64_t>(std::addressof(key));
            return static_cast<int>(syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, std::addressof(attr), sizeof(attr)));
        }
    }

    inline int InfinityRlLimit() noexcept
    {
        rlimit rl{};
        if (getrlimit(RLIMIT_MEMLOCK, std::addressof(rl)) == 0) {
            if (rl.rlim_max != RLIM_INFINITY || rl.rlim_cur != rl.rlim_max) {
                rl.rlim_max = RLIM_INFINITY;
                rl.rlim_cur = rl.rlim_max;
                return setrlimit(RLIMIT_MEMLOCK, std::addressof(rl));
            }
            return 0;
        }
        return -1;
    }
}

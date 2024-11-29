#pragma once

#include "libcu.h"
#include "CuFile.h"
#include "CuFormat.h"
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

namespace CU 
{
    namespace Bpf
    {
        inline int OpenObject(const std::string &path)
        {
            union bpf_attr attr = {
                .pathname = (uint64_t)path.data(),
            };
            return (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
        }

        inline int ProgAttachTracePoint(int progFd, const std::string &tracePoint)
        {
            struct perf_event_attr perfEventAttr{};
            perfEventAttr.config = CU::StrToULong(CU::ReadFile(CU::Format("/sys/kernel/tracing/events/{}/id", tracePoint)));
            perfEventAttr.type = PERF_TYPE_TRACEPOINT;
            perfEventAttr.sample_period = 1;
            perfEventAttr.wakeup_events = 1;
            int targetFd = syscall(__NR_perf_event_open, &perfEventAttr, -1, 0, -1, 0);
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
        inline _Val_Ty GetElementValue(int fd, _Key_Ty key, _Val_Ty defaultValue) noexcept
        {
            auto elemKey = key;
            auto elemValue = defaultValue;
            union bpf_attr attr = {
                .map_fd = (uint32_t)fd,
                .key = (uint64_t)(&elemKey),
                .value = (uint64_t)(&elemValue),
            };
            syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
            return elemValue;
        }
    }
}

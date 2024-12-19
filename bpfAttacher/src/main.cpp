// BPF Attacher by chenzyadb@github.com

#include "utils/cu_libbpf.h"
#include "utils/CuSched.h"
#include "utils/CuLogger.h"

constexpr char DAEMON_NAME[] = "bpfDaemon";

std::vector<std::string> ParseArgs(int argc, char* argv[])
{
    std::vector<std::string> args{};
    for (int idx = 0; idx < argc; idx++) {
        args.emplace_back(argv[idx]);
    }
    size_t argv_size = 0;
    for (const auto &arg : args) {
        argv_size += arg.size() + 1;
    }
    memset(argv[0], 0, argv_size);
    strncpy(argv[0], DAEMON_NAME, sizeof(DAEMON_NAME));
    return args;
}

void DaemonMain(const std::string &programName, const std::vector<std::string> &tracePoints)
{
    static const auto attachToTracePoint = [](const std::string &progName, const std::string &tracePoint) -> int {
        static constexpr char bpf_path[] = "/sys/fs/bpf";

        auto tracePointCategory = CU::SubPrevStr(tracePoint, '/');
        auto tracePointName = CU::SubPostStr(tracePoint, '/');
        auto progObject = CU::Format("prog_{}_tracepoint_{}_{}", progName, tracePointCategory, tracePointName);
        auto bpfObjects = CU::ListFile(bpf_path, DT_REG);
        for (const auto &bpfObject : bpfObjects) {
            if (bpfObject == progObject) {
                int progFd = CU::Bpf::OpenObject(CU::Format("{}/{}", bpf_path, bpfObject));
                if (progFd >= 0) {
                    return CU::Bpf::ProgAttachTracePoint(progFd, tracePoint);
                }
            }
        }
        return -1;
    };

    CU::SetThreadName(DAEMON_NAME);
    CU::SetTaskSchedPrio(0, 120);

    for (const auto &tracePoint : tracePoints) {
        if (attachToTracePoint(programName, tracePoint) >= 0) {
            CU::Logger::Info("The attachment of program \"{}\" to tracepoint \"{}\" succeeded.", programName, tracePoint);
        } else {
            CU::Logger::Warn("The attachment of program \"{}\" to tracepoint \"{}\" failed.", programName, tracePoint);
        }
    }

    CU::Logger::Info("Daemon Running (pid={}).", getpid());
    CU::Pause();
}

int main(int argc, char* argv[])
{
    std::string logPath = "/data/bpf_daemon.log";
    std::string programName{};
    std::vector<std::string> tracePoints{};

    auto args = ParseArgs(argc, argv);
    for (size_t idx = 1; idx < args.size(); idx++) {
        if (args[idx] == "--log" && (idx + 1) < args.size()) {
            logPath = args[++idx];
        } else if (args[idx] == "--program" && (idx + 1) < args.size()) {
            programName = args[++idx];
        } else if (args[idx] == "--add-tracepoint" && (idx + 1) < args.size()) {
            tracePoints.emplace_back(args[++idx]);
        } else {
            CU::Println("Invalid Arguments.");
            return -1;
        }
    }
    if (programName.size() == 0 || tracePoints.size() == 0) {
        return 0;
    }

    CU::Println("Daemon Start.");
    daemon(0, 0);
    CU::Logger::Create(CU::Logger::LogLevel::VERBOSE, logPath);
    CU::Logger::Info("BPF Daemon by chenzyadb@github.com");
    DaemonMain(programName, tracePoints);

    return 0;
}

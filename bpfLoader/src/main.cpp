#include "utils/cu_libbpf.h"
#include "utils/cu_elf.h"
#include "utils/CuPairList.h"

constexpr char BPF_PATH[] = "/sys/fs/bpf";

int LoadProg(const std::string &path)
{
    static const auto getMapSections = [](const CU::Elf::Sections &sections) -> CU::Elf::Sections {
        CU::Elf::Sections mapSections{};
        for (const auto &section : sections) {
            if (section.type == SHT_PROGBITS && CU::StrStartsWith(section.name, "bpf_map_")) {
                mapSections.emplace_back(section);
            }
        }
        return mapSections;
    };
    static const auto getBpfMapName = [](const CU::Elf::Section &section) -> std::string {
        return CU::SubPostStr(section.name, "bpf_map_");
    };
    static const auto getProgSections = [](const CU::Elf::Sections &sections) -> CU::Elf::Sections {
        CU::Elf::Sections progSections{};
        for (const auto &section : sections) {
            if (section.type == SHT_PROGBITS && CU::StrStartsWith(section.name, "bpf_prog_")) {
                progSections.emplace_back(section);
            }
        }
        return progSections;
    };
    static const auto getBpfProgName = [](const CU::Elf::Section &section) -> std::string {
        return CU::Replace(CU::SubPostStr(section.name, "bpf_prog_"), '/', '_');
    };
    static const auto getBpfProgType = [](const CU::Elf::Section &section) -> bpf_prog_type {
        static const std::unordered_map<std::string, bpf_prog_type> progTypesMap = {
            {"bpf_prog_skfilter", BPF_PROG_TYPE_SOCKET_FILTER},
            {"bpf_prog_kprobe", BPF_PROG_TYPE_KPROBE},
            {"bpf_prog_uprobe", BPF_PROG_TYPE_KPROBE},
            {"bpf_prog_schedcls", BPF_PROG_TYPE_SCHED_CLS},
            {"bpf_prog_tracepoint", BPF_PROG_TYPE_TRACEPOINT},
            {"bpf_prog_xdp", BPF_PROG_TYPE_XDP},
            {"bpf_prog_perf_event", BPF_PROG_TYPE_PERF_EVENT},
            {"bpf_prog_cgroupskb", BPF_PROG_TYPE_CGROUP_SKB},
            {"bpf_prog_cgroupsock", BPF_PROG_TYPE_CGROUP_SOCK}
        };
        for (const auto &[name, type] : progTypesMap) {
            if (CU::StrStartsWith(section.name, name)) {
                return type;
            }
        }
        return BPF_PROG_TYPE_UNSPEC;
    };
    static const auto getProgInsns = 
        [](const CU::Elf::Sections &sections, const CU::Elf::Section &progSection, CU::PairList<int, std::string> bpfMaps)
        -> CU::Elf::Binary
    {
        auto progInsns = progSection.data;
        auto rels = CU::Elf::GetSectionByName(sections, CU::Format(".rel{}", progSection.name)).data;
        if (rels.size() > 0) {
            auto strtab = CU::Elf::GetSectionByType(sections, SHT_STRTAB).data;
            auto symtab = CU::Elf::GetSectionByType(sections, SHT_SYMTAB).data;
            for (size_t idx = 0; idx < (rels.size() / sizeof(Elf64_Rel)); idx++) {
                auto rel = reinterpret_cast<const Elf64_Rel*>(&rels[sizeof(Elf64_Rel) * idx]);
                auto symbol = reinterpret_cast<const Elf64_Sym*>(&symtab[sizeof(Elf64_Sym) * ELF64_R_SYM(rel->r_info)]);
                auto symbolName = &strtab[symbol->st_name];
                if (bpfMaps.containsValue(symbolName)) {
                    auto insn = reinterpret_cast<bpf_insn*>(&progInsns[rel->r_offset]);
                    if (insn->code == (BPF_LD | BPF_IMM | BPF_DW)) {
                        insn->imm = bpfMaps.atValue(symbolName);
                        insn->src_reg = BPF_PSEUDO_MAP_FD;
                    }
                }
            }
        }
        return progInsns;
    };

    CU::InfinityRlLimit();

    if (!CU::IsPathExists(BPF_PATH)) {
        CU::Println("[-] Bpf path not exists.");
        return -1;
    }

    if (!CU::StrEndsWith(path, ".o")) {
        CU::Println("[-] Invalid bpf program file.");
        return -1;
    }

    auto progName = CU::SubPrevStr(CU::SubRePostStr(path, '/'), ".o");
    if (progName.size() == 0) {
        CU::Println("[-] Failed to get bpf program name.");
        return -1;
    }

    auto sections = CU::Elf::ReadSections(path);
    if (sections.size() == 0) {
        CU::Println("[-] Failed to read sections.");
        return -1;
    }

    std::string license("GPL");
    auto licenseSection = CU::Elf::GetSectionByName(sections, "license");
    if (licenseSection.data.size() > 0) {
        license = licenseSection.data.data();
    }
    CU::Println("[+] Bpf program license: \"{}\".", license);

    CU::PairList<int, std::string> bpfMaps{};

    auto mapSections = getMapSections(sections);
    if (mapSections.size() > 0) {
        for (const auto &mapSection : mapSections) {
            auto bpfMapName = getBpfMapName(mapSection);
            auto bpfMapDef = reinterpret_cast<const cu_bpf_map_def*>(mapSection.data.data());
            int mapFd = CU::Bpf::CreateMap(bpfMapDef->type, bpfMapDef->key_size, bpfMapDef->value_size,
                bpfMapDef->max_entries, bpfMapDef->map_flags);
            if (mapFd < 0) {
                CU::Println("[-] Failed to create map \"{}\".", bpfMapName);
                return -1;
            }

            auto bpfMapPath = CU::Format("{}/map_{}_{}", BPF_PATH, progName, bpfMapName);
            if (CU::IsPathExists(bpfMapPath)) {
                CU::Println("[-] Map \"{}\" already exists.", bpfMapPath);
                return -1;
            }

            CU::Bpf::PinObject(mapFd, bpfMapPath);
            CU::Println("[+] Successfully created map \"{}\".", bpfMapName);

            bpfMaps.add(mapFd, bpfMapName);
        }
    }

    auto progSections = getProgSections(sections);
    if (progSections.size() > 0) {
        for (const auto &progSection : progSections) {
            auto bpfProgType = getBpfProgType(progSection);
            auto bpfProgName = getBpfProgName(progSection);
            auto progInsns = getProgInsns(sections, progSection, bpfMaps);
            int progFd = CU::Bpf::LoadProgram(bpfProgType, reinterpret_cast<const bpf_insn*>(progInsns.data()),
                progInsns.size(), license);
            if (progFd < 0) {
                CU::Println("[-] Failed to load program \"{}\".", bpfProgName);
                return -1;
            }

            auto bpfProgPath = CU::Format("{}/prog_{}_{}", BPF_PATH, progName, bpfProgName);
            if (CU::IsPathExists(bpfProgPath)) {
                CU::Println("[-] Program \"{}\" already exists.", bpfProgPath);
                return -1;
            }

            if (CU::Bpf::PinObject(progFd, bpfProgPath) < 0) {
                CU::Println("[-] Failed to pin object at \"{}\".", bpfProgPath);
                return -1;
            }

            CU::Println("[+] Successfully loaded program \"{}\".", bpfProgName);
        }
    }

    return 0;
}

int main(int argc, char* argv[]) 
{
    if (argc == 2) {
        std::string progPath(argv[1]);
        if (CU::IsPathExists(progPath)) {
            CU::Println("[+] Loading bpf program \"{}\".", progPath);
            return LoadProg(argv[1]);
        }
    }
    CU::Println("[-] Invaild Arguments.");
    return -1;
}

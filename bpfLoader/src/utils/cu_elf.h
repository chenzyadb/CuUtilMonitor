#pragma once

#include "libcu.h"
#include <cstdio>
#include <linux/elf.h>

namespace CU 
{
    namespace Elf 
    {
        typedef std::vector<char> Binary;

        struct Section {
            std::string name;
            Elf64_Word type;
            Binary data;
        };

        typedef std::vector<Section> Sections;

        inline Binary ReadBinary(const std::string &path)
        {
            Binary binary{};

            auto fp = std::fopen(path.c_str(), "rb");
            if (fp == nullptr) {
                return binary;
            }

            size_t readBytes = 0;
            char buffer[4096]{};
            while ((readBytes = std::fread(buffer, 1, sizeof(buffer), fp)) > 0) {
                binary.insert(binary.end(), buffer, (buffer + readBytes));
            }
            std::fclose(fp);

            return binary;
        }

        inline Sections ReadSections(const std::string &path)
        {
            auto rawData = ReadBinary(path);
            if (rawData.size() == 0) {
                return {};
            }

            auto elfHeader = reinterpret_cast<const Elf64_Ehdr*>(&rawData[0]);
            if (elfHeader->e_ehsize == 0) {
                return {};
            }

            const char* strtab = nullptr;
            for (Elf64_Half idx = 0; idx < elfHeader->e_shnum; idx++) {
                auto sectionHeaderOffset = elfHeader->e_shoff + elfHeader->e_shentsize * idx;
                auto sectionHeader = reinterpret_cast<const Elf64_Shdr*>(&rawData[sectionHeaderOffset]);
                if (sectionHeader->sh_type == SHT_STRTAB && sectionHeader->sh_offset > 0) {
                    strtab = &rawData[sectionHeader->sh_offset];
                    break;
                }
            }
            if (strtab == nullptr) {
                return {};
            }

            Sections sections(elfHeader->e_shnum);
            for (size_t idx = 0; idx < sections.size(); idx++) {
                auto sectionHeaderOffset = elfHeader->e_shoff + elfHeader->e_shentsize * idx;
                auto sectionHeader = reinterpret_cast<const Elf64_Shdr*>(&rawData[sectionHeaderOffset]);
                sections[idx].name = strtab + sectionHeader->sh_name;
                sections[idx].type = sectionHeader->sh_type;
                if (sectionHeader->sh_offset > 0 && sectionHeader->sh_size > 0) {
                    sections[idx].data.insert(sections[idx].data.begin(), &rawData[sectionHeader->sh_offset], 
                        &rawData[sectionHeader->sh_offset + sectionHeader->sh_size]);
                }
            }
            return sections;
        }

        inline Section GetSectionByName(const Sections &sections, const std::string &name)
        {
            for (auto iter = sections.begin(); iter < sections.end(); ++iter) {
                if (iter->name == name) {
                    return *iter;
                }
            }
            return {};
        }

        inline Section GetSectionByType(const Sections &sections, Elf64_Word type)
        {
            for (auto iter = sections.begin(); iter < sections.end(); ++iter) {
                if (iter->type == type) {
                    return *iter;
                }
            }
            return {};
        }
    }
}

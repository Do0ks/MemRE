#include "GOffsets.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <windows.h>
#include <Psapi.h>

// Reads the binary file.
std::vector<Byte> readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return {};
    }
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    std::vector<Byte> buffer(fileSize);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    return buffer;
}

// Signatures
std::vector<Signature> getSignatures() {
    std::vector<Signature> sigs;
    // ----------------------------------------------
    // START GWORLDS
    // ----------------------------------------------
    sigs.push_back({ "GWorld (Variant 1)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x8B, 0x00, 0x00, 0x00,
         0xF6, 0x86, 0x3B, 0x01, 0x00, 0x00,
         0x40},
        "xxx?????x???xxxxxxx"
        });

    sigs.push_back({ "GWorld (Variant 2)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x8B, 0x00, 0x00, 0xF6,
         0x86, 0x3B, 0x01, 0x00, 0x00, 0x40},
        "xxx?????x??xxxxxxx"
        });

    sigs.push_back({ "GWorld (Variant 3)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x8B, 0x00, 0x00, 0x00,
         0x00, 0x00, 0xF6, 0x86, 0x00, 0x01,
         0x00, 0x00, 0x40},
        "xxx?????x?????xx?xxxx"
        });

    sigs.push_back({ "GWorld (Variant 4)",
        {0x00, 0x8B, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x48, 0x89, 0x05, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x8B, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00},
        "?x???xx?xxx?????x???xx?????x?"
        });

    sigs.push_back({ "GWorld (Variant 5)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00,
         0x02, 0x48, 0x8B, 0x8F, 0xA0, 0x00,
         0x00, 0x00},
        "xxx???xxxxx???"
        }); // IDK about this AOB.

    sigs.push_back({ "GWorld (Variant 6)",
        {0x48, 0x89, 0x05, 0x00, 0x00, 0x00,
         0x00, 0x49, 0x8B, 0x00, 0x78, 0xF6,
         0x00, 0x3B, 0x01, 0x00, 0x00, 0x40},
        "xxx????xx?xx?xx??x"
        });
    // ----------------------------------------------
    // END GWORLDS
    // ----------------------------------------------

    // ----------------------------------------------
    // START GNAMES
    // ----------------------------------------------
    sigs.push_back({ "GNames (Variant 1)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0xE8, 0x00, 0x00, 0xFE, 0xFF,
         0x4C, 0x8B, 0xC0, 0xC6, 0x05, 0x00,
         0x00, 0x00, 0x00, 0x01},
        "xxx????x??xxxxxxx????x"
        });

    sigs.push_back({ "GNames (Variant 2)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00,
         0x03, 0xE8, 0x00, 0x00, 0xFF, 0xFF,
         0x4C, 0x00, 0xC0},
        "xxx???xx??xxx?x"
        });

    sigs.push_back({ "GNames (Variant 3)",
        {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0xE8, 0x00, 0x00, 0xFF, 0xFF,
         0x48, 0x8B, 0xD0, 0xC6, 0x05, 0x00,
         0x00, 0x00, 0x00, 0x01},
        "xxx????x??xxxxxxx????x"
        });

    sigs.push_back({ "GNames (Variant 4)",
        {0x48, 0x8B, 0X05, 0X00, 0x00, 0x00,
         0x02, 0x48, 0x85, 0xC0, 0x75, 0x5F,
         0xB9, 0x08, 0x08, 0x00},
        "xxx???xxxxxxxxx?"
        });
    // ----------------------------------------------
    // END GNAMES
    // ----------------------------------------------

    // ----------------------------------------------
    // START GOBJECTS
    // ----------------------------------------------
    sigs.push_back({ "GObjects (Variant 1)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0x99, 0x0F, 0xB7, 0xD2},
        "xxx????xxxx"
        });

    sigs.push_back({ "GObjects (Variant 2)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0x41, 0x3B, 0xC0, 0x7D, 0x17},
        "xxx????xxxxx"
        });

    sigs.push_back({ "GObjects (Variant 3)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00,
         0x04, 0x90, 0x0F, 0xB7, 0xC6, 0x8B,
         0xD6},
        "xxx???xxxxxxx"
        });

    sigs.push_back({ "GObjects (Variant 4)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00,
         0x04, 0x90, 0x0F, 0xB7, 0xC6, 0x8B,
         0xD6},
        "xxx???xxxxxxx"
        });

    sigs.push_back({ "GObjects (Variant 5)",
        {0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00,
         0x00, 0x8B, 0xD0, 0xC1, 0xEA, 0x10},
        "xxx????xxxxx"
        });
    // ----------------------------------------------
    // END GOBJECTS
    // ----------------------------------------------

    return sigs;
}

// Searches for a pattern.
size_t findPatternMask(const std::vector<Byte>& data,
    const std::vector<Byte>& pattern,
    const std::string& mask) {
    if (pattern.size() != mask.size() || pattern.empty() || data.empty())
        return std::string::npos;
    for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found)
            return i;
    }
    return std::string::npos;
}

// Calculates adjustments to convert offsets within the PE.
uint32_t getSectionDelta(const std::vector<Byte>& data, size_t offset) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER))
        return 0;
    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dosHeader->e_magic != 0x5A4D) // "MZ"
        return 0;
    size_t peHeaderOffset = dosHeader->e_lfanew;
    if (data.size() < peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER))
        return 0;
    const uint32_t* peSignature = reinterpret_cast<const uint32_t*>(data.data() + peHeaderOffset);
    if (*peSignature != 0x00004550) // "PE\0\0"
        return 0;
    const IMAGE_FILE_HEADER* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(data.data() + peHeaderOffset + sizeof(uint32_t));
    size_t optHeaderOffset = peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
    size_t sectionHeadersStart = optHeaderOffset + fileHeader->SizeOfOptionalHeader;
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        const IMAGE_SECTION_HEADER* section =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(data.data() + sectionHeadersStart + i * sizeof(IMAGE_SECTION_HEADER));
        uint32_t rawStart = section->PointerToRawData;
        uint32_t rawEnd = rawStart + section->SizeOfRawData;
        if (offset >= rawStart && offset < rawEnd) {
            return section->VirtualAddress - section->PointerToRawData;
        }
    }
    return 0;
}

// Memory scanning fallback to find offsets in the process memory.
uint64_t findOffsetInProcessMemory(HANDLE hProcess, const std::vector<Byte>& pattern, const std::string& mask, const std::string& group) {
    HMODULE hMod;
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        return 0;
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo)))
        return 0;
    std::vector<Byte> buffer(modInfo.SizeOfImage);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, buffer.data(), modInfo.SizeOfImage, &bytesRead))
        return 0;
    size_t foundOffset = findPatternMask(buffer, pattern, mask);
    if (foundOffset == std::string::npos || foundOffset + 7 > buffer.size())
        return 0;
    foundOffset = adjustFoundOffsetForGroup(buffer, foundOffset, group);
    int32_t disp = *reinterpret_cast<const int32_t*>(&buffer[foundOffset + 3]);
    size_t nextInstr = foundOffset + 7;
    size_t rawAddress = nextInstr + disp;
    uint64_t rva = rawAddress;
    return rva;
}

// Adjusts the found offset based on a group-specific prefix.
// For example, if scanning for "GWorld", we may search nearby for a known instruction prefix.
size_t adjustFoundOffsetForGroup(const std::vector<Byte>& data, size_t foundOffset, const std::string& group) {
    std::vector<std::vector<Byte>> prefixes;
    if (group == "GWorld") {
        prefixes.push_back({ 0x48, 0x89, 0x05 });
    }
    else if (group == "GNames") {
        prefixes.push_back({ 0x48, 0x8D, 0x0D }); // <= 4.27
        prefixes.push_back({ 0x48, 0x8B, 0x05 }); // > 4.27
    }
    else if (group == "GObjects") {
        prefixes.push_back({ 0x4C, 0x8B, 0x0D });
    }
    else {
        return foundOffset;
    }
    size_t searchLimit = 30;
    size_t limit = (foundOffset + searchLimit < data.size()) ? foundOffset + searchLimit : data.size();
    for (size_t i = foundOffset; i <= limit; i++) {
        for (const auto& prefix : prefixes) {
            if (i + prefix.size() > data.size())
                continue;
            bool match = true;
            for (size_t j = 0; j < prefix.size(); j++) {
                if (data[i + j] != prefix[j]) {
                    match = false;
                    break;
                }
            }
            if (match)
                return i;
        }
    }
    return foundOffset;
}
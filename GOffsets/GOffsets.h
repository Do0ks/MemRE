#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <vector>
#include <string>
#include <cstdint>
#include <windows.h>


using Byte = unsigned char;

struct Signature {
    std::string name;
    std::vector<Byte> pattern;
    std::string mask;
};

std::vector<Byte> readBinaryFile(const std::string& filename);
std::vector<Signature> getSignatures();

// 'x' = fixed byte, '?' = wildcard.
size_t findPatternMask(const std::vector<Byte>& data,
    const std::vector<Byte>& pattern,
    const std::string& mask);

uint32_t getSectionDelta(const std::vector<Byte>& data, size_t offset);
uint64_t findOffsetInProcessMemory(HANDLE hProcess, const std::vector<Byte>& pattern, const std::string& mask, const std::string& group);

// Adjusts the found offset based on expected prefixes.
size_t adjustFoundOffsetForGroup(const std::vector<Byte>& data, size_t foundOffset, const std::string& group);


#endif
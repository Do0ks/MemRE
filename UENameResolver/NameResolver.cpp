#include "NameResolver.h"
#include "../GOffsets/GOffsets.h" 
#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

uintptr_t g_nameFieldOffset = 0;
uint64_t  g_GNames = 0;
int       g_nameVerMajor = 0;
int       g_nameVerMinor = 0;

bool InitGNames(HANDLE hProc, uintptr_t moduleBase, const std::string& versionStr)
{
    // parse "4.22.3.0" → major=4, minor=22
    std::string tmp = versionStr;
    for (char& c : tmp) if (!isdigit((unsigned char)c)) c = ' ';
    std::istringstream iss(tmp);
    iss >> g_nameVerMajor >> g_nameVerMinor;

    // scan all your signatures for "GNames"
    uint64_t rawRVA = 0;
    for (auto& sig : getSignatures()) {
        if (sig.name.find("GNames") != std::string::npos) {
            rawRVA = findOffsetInProcessMemory(hProc, sig.pattern, sig.mask, "GNames");
            if (rawRVA) break;
        }
    }
    if (!rawRVA) return false;

    uint64_t addr = moduleBase + rawRVA;
    uint64_t namesPtr = 0;

    // UE4.22‑ and earlier store a pointer here
    if (g_nameVerMajor == 4 && g_nameVerMinor <= 22) {
        if (!ReadProcessMemory(hProc, (LPCVOID)addr, &namesPtr, sizeof(namesPtr), nullptr))
            return false;
    }
    else {
        // UE4.23+ and UE5: this _is_ the start of the FNameEntry* array
        namesPtr = addr;
    }

    if (!namesPtr) return false;
    g_GNames = namesPtr;
    return true;
}

std::wstring GetFNameString(HANDLE hProc, uint32_t nameIndex)
{
    if (!g_GNames)
        return L"";

    // temp buffer for raw name bytes
    char buf[1024] = { 0 };
    uint32_t nameLen = 0;

    // ── UE4.22 and earlier: chunked IndirectArray<FNameEntry> ──
    if (g_nameVerMajor == 4 && g_nameVerMinor <= 22)
    {
        constexpr uint32_t ElementsPerChunk = 0x4000;
        uint32_t chunkIdx = nameIndex / ElementsPerChunk;
        uint32_t withinChunk = nameIndex % ElementsPerChunk;

        // read pointer to the chunk (gnames + 8*chunkIdx + poolOffset)
        uint64_t chunkPtr = 0;
        uint64_t chunkAddr = g_GNames + 8ull * chunkIdx; //If a GNames offset is required, add + offset
        if (!ReadProcessMemory(hProc, (LPCVOID)chunkAddr, &chunkPtr, sizeof(chunkPtr), nullptr))
            return L"";

        // read the actual FNameEntry* from that chunk
        uint64_t entryPtr = 0;
        uint64_t entryAddr = chunkPtr + 8ull * withinChunk;
        if (!ReadProcessMemory(hProc, (LPCVOID)entryAddr, &entryPtr, sizeof(entryPtr), nullptr))
            return L"";

        // ANSI string is at +0xC on 4.22, +0x10 otherwise
        uint64_t nameAddr = entryPtr
            + ((g_nameVerMajor == 4 && g_nameVerMinor == 22) ? 0xC : 0x10);
        if (!ReadProcessMemory(hProc, (LPCVOID)nameAddr, buf, sizeof(buf) - 1, nullptr))
            return L"";

        nameLen = static_cast<uint32_t>(strnlen_s(buf, sizeof(buf)));
    }
    // ── UE4.23+ / UE5.x: flat TNameEntryArray<FNameEntry*> ──
    else
    {
        // split index into high‑word chunk and low‑word offset
        uint32_t chunkOffset = nameIndex >> 16;
        uint16_t nameOffset = static_cast<uint16_t>(nameIndex);

        // read the base pointer for this chunk (skip two header fields)
        uint64_t chunkBase = 0;
        uint64_t ptrAddr = g_GNames + 8ull * (chunkOffset + 2);
        if (!ReadProcessMemory(hProc, (LPCVOID)ptrAddr, &chunkBase, sizeof(chunkBase), nullptr))
            return L"";

#if WITH_CASE_PRESERVING_NAME
        // each entry: [Index:uint32][Len:uint16][UTF‑16 chars…]
        uint64_t poolPtr = chunkBase + 4ull * nameOffset;
        uint16_t rawLen = 0;
        ReadProcessMemory(hProc, (LPCVOID)(poolPtr + 4), &rawLen, sizeof(rawLen), nullptr);
        nameLen = rawLen >> 1;
        ReadProcessMemory(hProc, (LPCVOID)(poolPtr + 6), buf, nameLen, nullptr);
#else
        // each entry: [Hdr:uint16][ANSI chars…], length = Hdr>>6
        uint64_t poolPtr = chunkBase + 2ull * nameOffset;
        uint16_t rawHdr = 0;
        ReadProcessMemory(hProc, (LPCVOID)poolPtr, &rawHdr, sizeof(rawHdr), nullptr);
        nameLen = rawHdr >> 6;
        ReadProcessMemory(hProc, (LPCVOID)(poolPtr + 2), buf, nameLen, nullptr);
#endif
    }

    if (nameLen == 0)
        return L"";

    // ANSI→UTF‑16
    int wlen = MultiByteToWideChar(CP_ACP, 0, buf, nameLen, nullptr, 0);
    std::wstring result(wlen, L'\0');
    MultiByteToWideChar(CP_ACP, 0, buf, nameLen, &result[0], wlen);
    return result;
}
#pragma once
#include <Windows.h>
#include <string>
#include <cstdint>

extern uintptr_t g_nameFieldOffset;
extern uint64_t  g_GNames;
extern int       g_nameVerMajor;
extern int       g_nameVerMinor;

bool InitGNames(HANDLE hProc, uintptr_t moduleBase, const std::string& versionStr);

std::wstring GetFNameString(HANDLE hProc, uint32_t nameIndex);
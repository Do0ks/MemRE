#ifndef UE_VERSION_SCANNER_H
#define UE_VERSION_SCANNER_H

#include <string>
#include <windows.h>

// Unreal Engine version detection functions.
std::string GetVersionFromResource(const std::string& filePath);
std::string GetVersionFromFiles(const std::string& filePath);
std::string GetVersionFromMemoryScan();
std::string GetVersionFromProcessMemory(HANDLE hProcess);
bool IsProcessRunning(const std::string& exeName, DWORD& processID);
std::string GetUnrealEngineVersion(const std::string& filePath, const std::string& exeName);

#endif
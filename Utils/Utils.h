#pragma once
#include <windows.h>
#include <string>
#include <string_view>
#include <cstddef>

extern HWND g_hOutputLog;

std::wstring trim(const std::wstring& s);
std::string WideToAnsi(const std::wstring& ws);
std::wstring FormatNumberWithCommas(size_t value);
void Log(std::wstring_view msg);
void AppendConsoleAsync(const char* text);
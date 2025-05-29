#include "Utils.h"
#include <sstream>
#include <windows.h>
#include <CommCtrl.h>

std::wstring trim(const std::wstring& s) {
    auto a = s.find_first_not_of(L" \t");
    if (a == std::wstring::npos) return L"";
    auto b = s.find_last_not_of(L" \t");
    return s.substr(a, b - a + 1);
}

std::string WideToAnsi(const std::wstring& w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], len, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

std::wstring FormatNumberWithCommas(size_t value)
{
    std::wstring num = std::to_wstring(value);
    int insertPos = static_cast<int>(num.length()) - 3;
    while (insertPos > 0)
    {
        num.insert(insertPos, L",");
        insertPos -= 3;
    }
    return num;
}

void Log(std::wstring_view msg)
{
    int len = GetWindowTextLengthW(g_hOutputLog);
    SendMessageW(g_hOutputLog, EM_SETSEL, len, len);
    std::wstring tmp(msg);
    SendMessageW(g_hOutputLog, EM_REPLACESEL, FALSE, (LPARAM)tmp.c_str());
}

void AppendConsoleAsync(const char* utf8)
{
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, &w[0], wlen);
    Log(w);
}
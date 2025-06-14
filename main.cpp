/*
 * MemRE - Injectable Memory Editor.
 * Author: Do0ks (https://github.com/Do0ks)
 * Copyright (c) 2025 Do0ks
 * License: MIT
 * Repository: https://github.com/Do0ks/MemRE
 * MemRE Loader: https://github.com/Do0ks/MemRELoader
 * Support: https://discord.gg/7nGkqwdJhn
 */


 //===========================================================================
 // Includes
 //===========================================================================

 /* Standard Library */
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <cstdint>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <queue>

/* Win32 / COMCTL */
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <uxtheme.h>
#include <shellapi.h>

/* Preprocessor includes */
#include "resource.h"
#include "GOffsets/GOffsets.h"
#include "UEVersionScanner/UEVersionScanner.h"
#include "UENameResolver/NameResolver.h"
#include "Utils/Utils.h"

/* Linker directives */
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "Psapi.lib")


//===========================================================================
// Definitions & Constants
//===========================================================================

/*=========== General Constants ===========*/
#define IDT_UPDATE_TIMER           1
#define UPDATE_INTERVAL_MS         500

#ifndef BS_FLAT
#define BS_FLAT                    0x8000
#endif

/*=========== Menu Commands ===========*/
#define ID_MENU_ATTACH             300
#define ID_MENU_PROCINFO           301
#define ID_MENU_THREAD             302
#define ID_MENU_SETTINGS           303
#define ID_MENU_HOTKEYS            304
#define ID_MENU_SUPPORT            305
#define IDM_COPY_MODULE_ADDR       40001

/*=========== Main Window Buttons ===========*/
#define IDC_BTN_FIRSTSCAN          103
#define IDC_BTN_NEXTSCAN           104
#define IDC_BTN_UNDOSCAN           105
#define IDC_BTN_NEWSCAN            106
#define IDC_BTN_ADDADDRESS         210
#define IDC_BTN_SAVETABLE          211
#define IDC_BTN_LOADTABLE          212
#define IDC_BTN_SAVECT             213
#define IDC_BTN_EXIT               200

/*=========== Scan Results & Saved Lists ===========*/
#define IDC_LIST_SCANRESULTS       107
#define IDC_LIST_SAVEDADDR         108
#define DEFAULT_DESC_WIDTH         126
#define DEFAULT_ADDR_WIDTH         100
#define DEFAULT_DESC_WIDTH         126
#define DEFAULT_ADDR_WIDTH         100

/*=========== Scan Status & Progress ===========*/
#define IDC_STATIC_SCANSTATUS      100
#define IDC_PROGRESS_BAR           110

/*=========== Value Input Controls ===========*/
#define IDC_EDIT_VALUE             101
#define IDC_COMBO_VALUETYPE        102
#define IDC_COMBO_SEARCHMODE       109

/*=========== Address Addition Dialog ===========*/
#define IDC_ADD_EDITADDRESS        501
#define IDC_ADD_COMBOTYPE          502
#define IDC_ADD_OK                 503
#define IDC_ADD_CANCEL             504

/*=========== Process List & Filtering ===========*/
#define IDC_PROCESS_LIST           200
#define IDC_FILTER_TAB             300

/*=========== Pointer‑Chain Frame ===========*/
#define IDC_CHAIN_FRAME            600
#define IDC_STATIC_BASE_ADDRESS    601
#define IDC_EDIT_BASE_ADDRESS      602
#define IDC_STATIC_DYNAMIC_ADDRESS 603
#define IDC_EDIT_DYNAMIC_ADDRESS   604
#define IDC_STATIC_MAXDEPTH        610
#define IDC_EDIT_MAXDEPTH          611
#define IDC_BTN_POINTERSCAN        612
#define IDC_BTN_VIEWPTRS           613
#define IDC_COMBO_PTRTABLE_TYPE    7002
#define IDM_PTRTABLE_DELETE        7003

/*=========== Pointer‑Chain Viewer ===========*/
#define IDC_BTN_SAVE_PTRS          7001
#define IDT_PTRTABLE_UPDATE        8001
#define PTRTABLE_UPDATE_MS         500

/*=========== Offsets Group ===========*/
#define IDC_GROUP_POSOFFSETS         620
#define IDC_LIST_OFFSETS             621
#define IDC_EDIT_OFFSETNEW           622
#define IDC_BTN_OFFSET_ADD           623
#define IDC_BTN_OFFSET_DEL           624
#define IDC_BTN_OFFSET_AUTO          625
#define IDC_OFFSET_CLEAR             630
#define IDC_CHECK_SCAN_SAVED_FILE    614

/*=========== Log Controls ===========*/
#define IDC_EDIT_LOG               700
#define IDC_CLEAR_LOGS             701
#define IDC_LOG_COPY               702
#define IDC_LOG_SELECTALL          703
#define IDC_LOG_PIN                704

/*===========General Constants==========*/
const size_t MAX_UNKNOWN_CANDIDATES = 400000000;
const size_t DISPLAY_LIMIT = 500;
const size_t MAPPED_PAGE_ENTRIES = 100000;

static constexpr DWORD_PTR MAX_OFFSET = 0xFFF;
static constexpr DWORD_PTR OFFSET_STEP = sizeof(DWORD_PTR);
static constexpr DWORD_PTR MAX_SUBOFFSET = 0x2000;

static double g_searchLow = 0.0;
static double g_searchHigh = 0.0;

/*===========Enums & Typedefs==========*/
enum DataType {
    DATA_BYTE,
    DATA_2BYTE,
    DATA_4BYTE,
    DATA_8BYTE,
    DATA_FLOAT,
    DATA_DOUBLE
};

enum SearchMode {
    SEARCH_EXACT,
    SEARCH_BIGGER,
    SEARCH_SMALLER,
    SEARCH_BETWEEN,
    SEARCH_UNKNOWN_INITIAL,
    SEARCH_INCREASED,
    SEARCH_DECREASED,
    SEARCH_CHANGED,
    SEARCH_UNCHANGED
};

/*===========Structs==========*/
struct ScanEntry {
    uintptr_t address;
    union {
        uint8_t  valByte;
        uint16_t val2Byte;
        uint32_t val4Byte;
        uint64_t val8Byte;
        float    valFloat;
        double   valDouble;
    } value;
    DataType dataType;
};

struct SavedEntry {
    bool freeze;
    ScanEntry entry;
    DataType savedType;
    std::wstring desc;
    std::wstring pointerExpr;
};

struct MemoryRegion {
    uintptr_t start;
    SIZE_T    size;
};

//===========================================================================
// UI Fonts
//===========================================================================
HFONT hHeaderFont = CreateFontW(
    -12, 0, 0, 0,
    FW_BOLD, FALSE, FALSE, FALSE,
    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
    VARIABLE_PITCH | FF_SWISS,
    L"Segoe UI"
);

HFONT hSmallFont = CreateFontW(
    -10, 0, 0, 0,
    FW_BOLD, FALSE, FALSE, FALSE,
    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
    VARIABLE_PITCH | FF_SWISS,
    L"Segoe UI"
);

HFONT hFont = CreateFontW(
    16, 0, 0, 0, FW_SEMIBOLD,
    FALSE, FALSE, FALSE,
    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
    DEFAULT_PITCH | FF_SWISS, L"Segoe UI"
);


//===========================================================================
// Forward Declarations
//===========================================================================

// — Core application entry & message loop
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD   WINAPI MainThread(LPVOID lpParam);
BOOL    APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// — Dialog procedures
LRESULT CALLBACK AddAddressDlgProc(HWND  hDlg, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK EditAddressDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK ProcessDialogProc(HWND  hDlg, UINT message, WPARAM wParam, LPARAM lParam);

// — In‐place edit controls
LRESULT CALLBACK SubItemEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static LRESULT CALLBACK EditOffsetProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// — List / log controls
static LRESULT CALLBACK OffsetsListProc(HWND  hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LogEditProc(HWND  hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static LRESULT CALLBACK BaseAddrEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static uintptr_t GetRemoteModuleBaseAddressByName(DWORD pid, const std::wstring& moduleName);
std::wstring DataTypeToString(DataType dt);
void UpdateScanResultsListView();

// — Window‐enumeration callbacks
BOOL CALLBACK EnumApplicationsProcW(HWND hwnd, LPARAM lParam);
BOOL CALLBACK EnumWindowsWindowsProcW(HWND    hwnd, LPARAM lParam);

// — Core logic helpers
class ScanResultPager;
void LoadTableFromFile(const std::wstring& filename);
void AppendSavedAddress(const SavedEntry& saved);
bool FindPreviousEntry(uintptr_t address, ScanEntry& prevEntry);
void SearchPositionalPointerPaths();
DWORD WINAPI PointerScanThreadProc(LPVOID lpParam);
LRESULT CALLBACK PointerTableProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// — Unreal Engine
void ShowAutoOffsetsDialog(HWND hParent, uintptr_t worldPtr);
static std::vector<std::pair<uintptr_t, uintptr_t>> g_autoOffsets;

// - WinProc Definitions
static LRESULT Handle_CopyData(HWND hWnd, LPARAM lParam);
static LRESULT Handle_CtlColorStatic(WPARAM wParam, LPARAM lParam);
static LRESULT Handle_Create(HWND hWnd, LPARAM lParam);
static LRESULT Handle_Timer(HWND hWnd);
static LRESULT Handle_Notify(HWND hWnd, WPARAM wParam, LPARAM lParam);
static LRESULT Handle_Command(HWND hWnd, WPARAM wParam, LPARAM lParam);
static LRESULT Handle_Destroy(HWND hWnd);

// (In‑place edit)
void SubclassEditControl(HWND hEdit);

// ScanResultPager is a class:
class ScanResultPager;

// Prototypes for “Show…” and “Select…” and “Inject/Attach…” helpers, 

void ShowEditAddressDialog(HWND hParent, int index);
void ShowAddAddressDialog(HWND hParent);

void SelectProcessDialog(HWND hParent);
void AttachToProcess(DWORD pid);
void InjectSelfIntoProcess(DWORD pid);

// (Saved‑entry re‑resolution)
void ResolvePendingSavedEntries();

// (UI Helpers)
void UpdateScanButtons(bool enabled);
void UpdateScanResultsListView();
void UpdateScanStatus();

// (Scan core)
bool PerformFirstScan(double searchVal, DataType dt, SearchMode searchMode);
bool PerformNextScan(double searchVal, DataType dt, SearchMode searchMode);
bool UndoScan();
void ResetScans();
bool GetSearchValueFromEdit(double& value);

//===========================================================================
// Global Variables
//===========================================================================

// — Folders & Scan IDs
std::wstring           g_scanResultsFolder;
std::wstring           g_tablesFolder;
int                    g_currentScanId = 0;
std::atomic<size_t>    g_candidateCount = 0;

// — Main window & controls
HWND                   g_hWndMain = nullptr;
HWND                   g_hStaticScanStatus = nullptr;
HWND                   g_hProgressBar = nullptr;
HWND                   g_hEditValue = nullptr;
HWND                   g_hComboValueType = nullptr;
HWND                   g_hBtnFirstScan = nullptr;
HWND                   g_hBtnNextScan = nullptr;
HWND                   g_hBtnUndoScan = nullptr;
HWND                   g_hBtnNewScan = nullptr;
HWND                   g_hListScanResults = nullptr;
HWND                   g_hListSavedAddresses = nullptr;
HWND                   g_hSubItemEdit = nullptr;
HWND                   g_hChainFrame = nullptr;
HWND                   g_hOutputLog = nullptr;
HWND                   g_hEditBaseAddress = nullptr;
HWND                   g_hDynamicAddressEdit = nullptr;

// — Positional‑offset controls
HWND                                          g_hStaticMaxDepth = nullptr;
HWND                                          g_hEditMaxDepth = nullptr;
HWND                                          g_hGroupPosOffsets = nullptr;
HWND                                          g_hListOffsets = nullptr;
HWND                                          g_hEditOffsetEntry = nullptr;
HWND                                          g_hBtnAddOffset = nullptr;
HWND                                          g_hBtnRemoveOffset = nullptr;
HWND                                          g_hBtnAutoOffset = nullptr;
HWND                                          g_hBtnPointerScan = nullptr;
HWND                                          g_hBtnViewPTRs = nullptr;
static HANDLE                                 g_hPointerScanThread = nullptr;
static std::atomic<bool>                      g_stopPointerScan = false;
static std::atomic<bool>                      g_isPointerScanning = false;
static std::vector<DWORD_PTR>                 g_initialPositionalOffsets;
static std::vector<DWORD_PTR>                 g_positionalOffsets;
static std::wstring                           g_mptrFilePath;
static std::vector<std::vector<std::wstring>> g_loadedChains;
static uintptr_t g_basePtrForDialog = 0;

// — In‑place edit state
int                    g_editingItem = -1;
int                    g_editingSubItem = -1;
WNDPROC                g_editOldProc = nullptr;
void EndSubItemEdit(HWND hEdit, bool commit);

// — Scan results & paging
ScanResultPager* g_scanPager = nullptr;
std::vector<ScanResultPager*>  g_undoStack;
size_t                         g_initialScanCount = 0;
std::vector<ScanEntry>         g_lastDisplayedEntries;
std::vector<bool>              g_itemChanged;
std::vector<ScanEntry>         g_firstScanEntries;
std::vector<ScanEntry>         g_previousScanEntries;
static uintptr_t ResolvePointerChain(HANDLE hProc, DWORD  pid, const std::vector<std::wstring>& parts);

// — Saved entries
std::vector<SavedEntry>        g_savedEntries;
static int                     g_pointerScanTargetIndex = -1;
static int                     g_editAddressIndex = -1;
//void ShowEditAddressDialog(HWND hParent, int index);

// — Process attachment state
bool                   g_isAttached = false;
bool                   g_unrealDetected = false;
HANDLE                 g_hTargetProcess = nullptr;
DWORD                  g_targetProcessId = 0;
DWORD                  g_targetPID = 0;
static HANDLE          g_hOriginalProcess = nullptr;
static DWORD           g_originalProcessId = 0;

// — Module handle & error flags
HMODULE                g_hModule = nullptr;
static uintptr_t       g_resolvedBaseAddress = 0;
static bool            g_suppressLoadErrors = false;
static bool            s_errorPromptShown = false;
static WNDPROC         g_oldOffsetEditProc = nullptr;
static WNDPROC         g_oldOffsetsProc = nullptr;
WNDPROC                g_oldLogProc = nullptr;
static bool            g_logPinned = false;
static size_t          g_pinnedLogLength = 0;
static WNDPROC         g_oldBaseAddrProc = NULL;

// — Numerical tolerances
const double           epsilon_double = 0.001;
const float            epsilon_float = 0.001f;


//===========================================================================
// Helper Functions
//===========================================================================

// - Scan Pager
class ScanResultPager {
public:
    ScanResultPager(const std::wstring& folder, size_t pageSizeEntries, int scanId)
        : m_folder(folder), m_pageSize(pageSizeEntries), m_totalEntries(0), m_scanId(scanId)
    {
        CreateNewPage();
    }
    ~ScanResultPager()
    {
        for (auto& page : m_pages)
        {
            if (page.data) UnmapViewOfFile(page.data);
            if (page.hMap) CloseHandle(page.hMap);
            if (page.hFile != INVALID_HANDLE_VALUE) CloseHandle(page.hFile);
            DeleteFileW(page.filePath.c_str());
        }
        m_pages.clear();
    }
    void Append(const ScanEntry& entry)
    {
        if (m_pages.empty() || m_pages.back().count >= m_pageSize)
        {
            if (!CreateNewPage())
                return;
        }
        MappedPage& page = m_pages.back();
        page.data[page.count] = entry;
        page.count++;
        m_totalEntries++;
    }
    bool GetEntry(size_t index, ScanEntry& entry) const
    {
        if (index >= m_totalEntries)
            return false;
        size_t pageIndex = index / m_pageSize;
        size_t indexInPage = index % m_pageSize;
        entry = m_pages[pageIndex].data[indexInPage];
        return true;
    }
    size_t Count() const { return m_totalEntries; }
private:
    struct MappedPage {
        HANDLE hFile;
        HANDLE hMap;
        ScanEntry* data;
        size_t count;
        std::wstring filePath;
    };
    bool CreateNewPage()
    {
        MappedPage page = { 0 };
        page.count = 0;
        std::wstringstream ss;
        ss << m_folder << L"\\scan_page_" << m_scanId << L"_" << m_pages.size() << L".dat";
        page.filePath = ss.str();
        HANDLE hFile = CreateFileW(page.filePath.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;
        page.hFile = hFile;
        LARGE_INTEGER liSize;
        liSize.QuadPart = m_pageSize * sizeof(ScanEntry);
        if (!SetFilePointerEx(hFile, liSize, NULL, FILE_BEGIN) || !SetEndOfFile(hFile))
        {
            CloseHandle(hFile);
            return false;
        }
        HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (hMap == NULL)
        {
            CloseHandle(hFile);
            return false;
        }
        page.hMap = hMap;
        ScanEntry* pData = (ScanEntry*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, m_pageSize * sizeof(ScanEntry));
        if (pData == NULL)
        {
            CloseHandle(hMap);
            CloseHandle(hFile);
            return false;
        }
        page.data = pData;
        m_pages.push_back(page);
        return true;
    }
    std::wstring m_folder;
    size_t m_pageSize;
    size_t m_totalEntries;
    int m_scanId;
    std::vector<MappedPage> m_pages;
};

// — File & Table I/O
static void AdjustSavedListColumns()
{
    int count = ListView_GetItemCount(g_hListSavedAddresses);
    const int shrink = 8;

    if (count >= 8)
    {
        ListView_SetColumnWidth(g_hListSavedAddresses, 1, DEFAULT_DESC_WIDTH - shrink);
        ListView_SetColumnWidth(g_hListSavedAddresses, 2, DEFAULT_ADDR_WIDTH - shrink);
    }
    else
    {
        ListView_SetColumnWidth(g_hListSavedAddresses, 1, DEFAULT_DESC_WIDTH);
        ListView_SetColumnWidth(g_hListSavedAddresses, 2, DEFAULT_ADDR_WIDTH);
    }
}

void CleanupDatFiles(const std::wstring& folder)
{
    std::wstring searchPattern = folder + L"\\*.dat";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do { std::wstring filePath = folder + L"\\" + findData.cFileName; DeleteFileW(filePath.c_str()); } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
}

void LoadTableFromFile(const std::wstring& filename)
{
    g_suppressLoadErrors = true;
    s_errorPromptShown = false;

    std::wifstream in(filename);
    if (!in) {
        MessageBoxW(g_hWndMain,
            (L"Cannot open file:\n" + filename).c_str(),
            L"Error", MB_OK | MB_ICONERROR);
        g_suppressLoadErrors = false;
        return;
    }

    g_savedEntries.clear();
    ListView_DeleteAllItems(g_hListSavedAddresses);

    std::wstring line;
    while (std::getline(in, line))
    {
        if (line.empty() || line[0] == L'#')
            continue;

        std::wistringstream peek(line);
        std::wstring firstTok, secondTok;
        std::getline(peek, firstTok, L',');
        std::getline(peek, secondTok, L',');

        bool full6col = (secondTok.size() == 1 && secondTok[0] >= L'0' && secondTok[0] <= L'5');
        SavedEntry s{};

        if (!full6col)
        {
            s.desc = firstTok;
            s.pointerExpr = line.substr(firstTok.size() + 1);
            s.freeze = false;
            s.savedType = s.entry.dataType = DATA_FLOAT;

            std::vector<std::wstring> parts;
            std::wstring tok;
            std::wistringstream ptrSS(s.pointerExpr);
            while (std::getline(ptrSS, tok, L','))
                parts.push_back(trim(tok));

            uintptr_t addr = ResolvePointerChain(
                g_hTargetProcess,
                g_targetProcessId,
                parts
            );
            s.entry.address = addr;
        }
        else
        {
            std::wistringstream ss(line);
            std::wstring addrTok, typeTok, valTok, freezeTok, descTok, ptrTok;
            std::getline(ss, addrTok, L',');
            std::getline(ss, typeTok, L',');
            std::getline(ss, valTok, L',');
            std::getline(ss, freezeTok, L',');
            std::getline(ss, descTok, L',');
            std::getline(ss, ptrTok);

            s.savedType = static_cast<DataType>(std::stoi(typeTok));
            s.entry.dataType = s.savedType;
            s.freeze = (freezeTok == L"1");
            s.desc = descTok;
            s.pointerExpr = ptrTok;

            if (s.pointerExpr.empty() && descTok.find(L',') != std::wstring::npos)
            {
                s.pointerExpr = descTok;
                s.desc.clear();
            }

            if (!s.pointerExpr.empty())
            {
                std::vector<std::wstring> parts;
                std::wstring tok;
                std::wistringstream ptrSS(s.pointerExpr);
                while (std::getline(ptrSS, tok, L','))
                    parts.push_back(trim(tok));

                uintptr_t addr = ResolvePointerChain(
                    g_hTargetProcess,
                    g_targetProcessId,
                    parts
                );
                s.entry.address = addr;
            }
            else
            {
                s.entry.address = static_cast<uintptr_t>(std::stoull(addrTok, nullptr, 16));
            }
        }

        HANDLE hProc = g_hTargetProcess;
        switch (s.savedType)
        {
        case DATA_BYTE: {
            uint8_t v = 0;
            ReadProcessMemory(hProc, (LPCVOID)s.entry.address, &v, sizeof(v), nullptr);
            s.entry.value.valByte = v;
        } break;
        case DATA_2BYTE: {
            uint16_t v = 0;
            ReadProcessMemory(hProc, (LPCVOID)s.entry.address, &v, sizeof(v), nullptr);
            s.entry.value.val2Byte = v;
        } break;
        case DATA_4BYTE: {
            uint32_t v = 0;
            ReadProcessMemory(hProc, (LPCVOID)s.entry.address, &v, sizeof(v), nullptr);
            s.entry.value.val4Byte = v;
        } break;
        case DATA_8BYTE: {
            uint64_t v = 0;
            ReadProcessMemory(hProc, (LPCVOID)s.entry.address, &v, sizeof(v), nullptr);
            s.entry.value.val8Byte = v;
        } break;
        case DATA_FLOAT: {
            float v = 0.0f;
            ReadProcessMemory(hProc, (LPCVOID)s.entry.address, &v, sizeof(v), nullptr);
            s.entry.value.valFloat = v;
        } break;
        case DATA_DOUBLE: {
            double v = 0.0;
            ReadProcessMemory(hProc, (LPCVOID)s.entry.address, &v, sizeof(v), nullptr);
            s.entry.value.valDouble = v;
        } break;
        }

        g_savedEntries.push_back(s);
        AppendSavedAddress(s);
    }

    g_suppressLoadErrors = false;
}

void AppendSavedAddress(const SavedEntry& saved)
{
    int index = ListView_GetItemCount(g_hListSavedAddresses);

    wchar_t addressStr[32];
    if (saved.entry.address == 0) {
        wcscpy_s(addressStr, 32, L"Pending…");
    }
    else {
        swprintf(addressStr, 32, L"%llX", (unsigned long long)saved.entry.address);
    }

    wchar_t typeStr[32];
    swprintf(typeStr, 32, L"%s", DataTypeToString(saved.savedType).c_str());

    wchar_t valueStr[64] = { 0 };
    switch (saved.entry.dataType)
    {
    case DATA_BYTE:   swprintf(valueStr, 64, L"%u", saved.entry.value.valByte);   break;
    case DATA_2BYTE:  swprintf(valueStr, 64, L"%u", saved.entry.value.val2Byte);  break;
    case DATA_4BYTE:  swprintf(valueStr, 64, L"%u", saved.entry.value.val4Byte);  break;
    case DATA_8BYTE:  swprintf(valueStr, 64, L"%llu", saved.entry.value.val8Byte); break;
    case DATA_FLOAT:  swprintf(valueStr, 64, L"%.4f", saved.entry.value.valFloat); break;
    case DATA_DOUBLE: swprintf(valueStr, 64, L"%.4f", saved.entry.value.valDouble); break;
    default:          swprintf(valueStr, 64, L"Unknown");                         break;
    }

    LVITEM lvItem = { 0 };
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = index;
    lvItem.pszText = const_cast<LPWSTR>(L"");
    int insertedIndex = ListView_InsertItem(g_hListSavedAddresses, &lvItem);

    ListView_SetCheckState(g_hListSavedAddresses, insertedIndex, saved.freeze);
    const wchar_t* descText = saved.desc.empty() ? L"N/A" : saved.desc.c_str();
    ListView_SetItemText(g_hListSavedAddresses, insertedIndex, 1, const_cast<LPWSTR>(descText));
    ListView_SetItemText(g_hListSavedAddresses, insertedIndex, 2, addressStr);
    ListView_SetItemText(g_hListSavedAddresses, insertedIndex, 3, typeStr);
    ListView_SetItemText(g_hListSavedAddresses, insertedIndex, 4, valueStr);
    ListView_SetItemText(g_hListSavedAddresses, insertedIndex, 5, const_cast<LPWSTR>(L"❌"));

    AdjustSavedListColumns();
}

bool FindPreviousEntry(uintptr_t address, ScanEntry& prevEntry)
{
    for (const auto& entry : g_previousScanEntries)
    {
        if (entry.address == address)
        {
            prevEntry = entry;
            return true;
        }
    }
    return false;
}

// — Pointer Resolution
static uintptr_t GetRemoteModuleBaseAddressByName(DWORD pid, const std::wstring& moduleName)
{
    MODULEENTRY32W me{ sizeof(me) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    if (Module32FirstW(hSnap, &me))
    {
        do {
            if (_wcsicmp(me.szModule, moduleName.c_str()) == 0)
            {
                CloseHandle(hSnap);
                return (uintptr_t)me.modBaseAddr;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return 0;
}

static uintptr_t ResolvePointerChain(HANDLE hProc, DWORD  pid, const std::vector<std::wstring>& parts)
{
    if (parts.empty())
        return 0;

    std::wstring first = trim(parts[0]);
    uintptr_t rawAddr = 0;
    auto plus = first.find(L'+');
    if (plus != std::wstring::npos) {
        std::wstring modName = trim(first.substr(0, plus));
        std::wstring offStr = trim(first.substr(plus + 1));
        uintptr_t baseAddr = GetRemoteModuleBaseAddressByName(pid, modName);
        if (!baseAddr) {
            if (!g_suppressLoadErrors && !s_errorPromptShown) {
                s_errorPromptShown = true;
                std::wstring msg = modName + L" not loaded. Do you want to clear the table?";
                int choice = MessageBoxW(
                    g_hWndMain,
                    msg.c_str(),
                    L"Error",
                    MB_YESNO | MB_ICONERROR
                );
                if (choice == IDYES) {
                    g_savedEntries.clear();
                    ListView_DeleteAllItems(g_hListSavedAddresses);
                }
            }
            return 0;
        }
        rawAddr = baseAddr + std::wcstoull(offStr.c_str(), nullptr, 16);
    }
    else {
        rawAddr = std::wcstoull(first.c_str(), nullptr, 16);
    }

    if (parts.size() == 1)
        return rawAddr;

    uintptr_t addr = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)rawAddr, &addr, sizeof(addr), nullptr)) {
        return 0;
    }

    for (size_t i = 1; i + 1 < parts.size(); ++i) {
        uintptr_t offset = std::wcstoull(trim(parts[i]).c_str(), nullptr, 16);
        uintptr_t next = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(addr + offset), &next, sizeof(next), nullptr)) {
            return 0;
        }
        addr = next;
    }

    uintptr_t lastOffset = std::wcstoull(trim(parts.back()).c_str(), nullptr, 16);
    addr += lastOffset;

    return addr;
}

void ShowPointerTableDialog(HWND hParent)
{
    // Compute max pointer‐depth
    size_t maxCols = 0;
    for (auto& chain : g_loadedChains)
        maxCols = (maxCols > chain.size()) ? maxCols : chain.size();

    // Register dialog window class once
    static bool reg = false;
    const wchar_t* cls = L"PointerTableDlg";
    if (!reg) {
        WNDCLASSW wc{ };
        wc.lpfnWndProc = PointerTableProc;
        wc.lpszClassName = cls;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassW(&wc);
        reg = true;
    }

    // Centered pop‑up
    RECT pr; GetWindowRect(hParent, &pr);
    int W = 100 + int((maxCols + 1) * 100), H = 400;
    int X = pr.left + ((pr.right - pr.left) - W) / 2;
    int Y = pr.top + ((pr.bottom - pr.top) - H) / 2;

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME, cls, L"Pointer Table",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        X, Y, W, H, hParent, nullptr, GetModuleHandleW(NULL), nullptr
    );
    ShowWindow(hDlg, SW_SHOW);
}

// Window‐proc for pointer‑table dialog
LRESULT CALLBACK PointerTableProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND      lv = nullptr;
    static HWND      btnSave = nullptr;
    static HWND      comboType = nullptr;
    static int       s_maxCols = 0;

    // Reusable lambda to fill the ListView according to the selected type
    auto BuildPointerTable = [&]() {
        int topIndex = ListView_GetTopIndex(lv);
        SendMessage(lv, WM_SETREDRAW, FALSE, 0);

        ListView_DeleteAllItems(lv);
        int selType = (int)SendMessageW(comboType, CB_GETCURSEL, 0, 0);
        int row = 0;
        for (const auto& chain : g_loadedChains) {
            // insert base & intermediate pointers
            LVITEMW item = { LVIF_TEXT };
            item.iItem = row;
            item.iSubItem = 0;
            item.pszText = const_cast<LPWSTR>(chain[0].c_str());
            ListView_InsertItem(lv, &item);
            for (int c = 1; c < (int)chain.size(); ++c)
                ListView_SetItemText(lv, row, c, const_cast<LPWSTR>(chain[c].c_str()));

            // blank‑out the Value column for now
            ListView_SetItemText(lv, row, s_maxCols, const_cast<LPWSTR>(L""));

            ++row;
        }

        // autosize all columns
        for (int i = 0; i <= s_maxCols; ++i)
            ListView_SetColumnWidth(lv, i, LVSCW_AUTOSIZE_USEHEADER);

        SendMessage(lv, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(lv, nullptr, FALSE);
        UpdateWindow(lv);
        ListView_EnsureVisible(lv, topIndex, FALSE);
    };

    auto RefreshPointerValues = [&]() {
        SendMessage(lv, WM_SETREDRAW, FALSE, 0);

        int selType = (int)SendMessageW(comboType, CB_GETCURSEL, 0, 0);
        int count = ListView_GetItemCount(lv);

        for (int row = 0; row < count; ++row) {
            const auto& chain = g_loadedChains[row];
            uintptr_t addr = ResolvePointerChain(g_hTargetProcess, g_targetProcessId, chain);

            wchar_t valBuf[64] = {};
            switch (selType) {
            case 0: {
                uint8_t  v; ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                swprintf(valBuf, 64, L"%u", v);
            } break;
            case 1: {
                uint16_t v; ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                swprintf(valBuf, 64, L"%u", v);
            } break;
            case 2: {
                uint32_t v; ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                swprintf(valBuf, 64, L"%u", v);
            } break;
            case 3: {
                uint64_t v; ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                swprintf(valBuf, 64, L"%llu", v);
            } break;
            case 4: {
                float f; ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &f, sizeof(f), nullptr);
                swprintf(valBuf, 64, L"%.4f", f);
            } break;
            case 5: {
                double d; ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &d, sizeof(d), nullptr);
                swprintf(valBuf, 64, L"%.4f", d);
            } break;
            }

            // update just the Value column
            ListView_SetItemText(lv, row, s_maxCols, valBuf);
        }

        SendMessage(lv, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(lv, nullptr, FALSE);
        UpdateWindow(lv);
    };

    auto DeleteSelectedChains = [&]() {
        // Collect all selected indices
        std::vector<int> selIndices;
        int idx = -1;
        while ((idx = ListView_GetNextItem(lv, idx, LVNI_SELECTED)) != -1) {
            selIndices.push_back(idx);
        }
        if (selIndices.empty())
            return;

        // Sort in descending order
        std::sort(selIndices.rbegin(), selIndices.rend());

        // Remove from ListView and from g_loadedChains
        for (int i : selIndices) {
            ListView_DeleteItem(lv, i);
            g_loadedChains.erase(g_loadedChains.begin() + i);
        }
    };

    switch (msg)
    {
    case WM_CREATE:
    {
        s_maxCols = 0;
        for (const auto& chain : g_loadedChains)
            s_maxCols = max(s_maxCols, (int)chain.size());

        RECT rc; GetClientRect(hwnd, &rc);
        lv = CreateWindowExW(0, WC_LISTVIEW, nullptr,
            WS_CHILD | WS_VISIBLE | LVS_REPORT,
            10, 10, rc.right - 20, rc.bottom - 100,
            hwnd, nullptr, GetModuleHandle(NULL), nullptr);
        ListView_SetExtendedListViewStyle(lv,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        // insert columns: Base Address, Pointer1…PointerN, Value
        LVCOLUMNW col = { LVCF_TEXT | LVCF_WIDTH };
        col.cx = 100; col.pszText = const_cast<LPWSTR>(L"Base Address");
        ListView_InsertColumn(lv, 0, &col);
        for (int i = 1; i <= s_maxCols; ++i) {
            col.cx = 100;
            wchar_t buf[32];
            if (i < s_maxCols)
                swprintf(buf, 32, L"Pointer %d", i);
            else
                wcscpy_s(buf, L"Value");
            col.pszText = buf;
            ListView_InsertColumn(lv, i, &col);
        }

        // Save button
        btnSave = CreateWindowW(L"BUTTON", L"Save Pointer Table",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            20, rc.bottom - 60, 160, 30,
            hwnd, (HMENU)IDC_BTN_SAVE_PTRS,
            GetModuleHandle(NULL), nullptr);

        // Type dropdown (Byte…Double)
        comboType = CreateWindowExW(WS_EX_CLIENTEDGE, L"COMBOBOX", nullptr,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            190, rc.bottom - 57, 120, 100,
            hwnd, (HMENU)IDC_COMBO_PTRTABLE_TYPE,
            GetModuleHandle(NULL), nullptr);
        const wchar_t* types[] = {
            L"Byte", L"2 Byte", L"4 Byte", L"8 Byte", L"Float", L"Double"
        };
        for (auto& t : types)
            SendMessageW(comboType, CB_ADDSTRING, 0, (LPARAM)t);
        SendMessageW(comboType, CB_SETCURSEL, 2, 0);

        BuildPointerTable();

        SetTimer(hwnd, IDT_PTRTABLE_UPDATE, PTRTABLE_UPDATE_MS, nullptr);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_COMBO_PTRTABLE_TYPE:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                BuildPointerTable();
            break;

        case IDC_BTN_SAVE_PTRS:
        {
            wchar_t outFile[MAX_PATH] = {};
            OPENFILENAMEW sfn{ sizeof(sfn) };
            sfn.hwndOwner = hwnd;
            sfn.lpstrFilter = L"Pointer files (*.MPTR)\0*.MPTR\0";
            sfn.lpstrFile = outFile;
            sfn.nMaxFile = MAX_PATH;
            sfn.lpstrDefExt = L"MPTR";
            sfn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
            if (GetSaveFileNameW(&sfn))
            {
                std::wofstream fout(sfn.lpstrFile, std::ios::trunc);
                for (const auto& c : g_loadedChains)
                {
                    fout << c[0];
                    for (size_t i = 1; i < c.size(); ++i)
                        fout << L"," << c[i];
                    fout << L"\n";
                }
            }
        }
        break;
        case IDM_PTRTABLE_DELETE:
            DeleteSelectedChains();
            break;
        }
        break;

    case WM_CONTEXTMENU:
        // right‑click on ListView, “Delete”
        if ((HWND)wParam == lv)
        {
            POINT pt;
            if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1)
                GetCursorPos(&pt);
            else {
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);
            }
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_PTRTABLE_DELETE, L"Delete");
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(hMenu);
        }
        break;

    case WM_NOTIFY:
    {
        NMHDR* pnmh = (NMHDR*)lParam;

        // 1) catch double‑clicks in our pointer‑table ListView
        if (pnmh->hwndFrom == lv && pnmh->code == NM_DBLCLK)
        {
            LPNMITEMACTIVATE act = (LPNMITEMACTIVATE)lParam;
            int idx = act->iItem;
            if (idx >= 0 && idx < (int)g_loadedChains.size())
            {
                // build a SavedEntry from the clicked chain
                SavedEntry saved{};
                saved.freeze = false;

                // 1) resolve its address
                auto& chain = g_loadedChains[idx];
                saved.entry.address = ResolvePointerChain(
                    g_hTargetProcess,
                    g_targetProcessId,
                    chain
                );

                // 2) pick up the selected data‑type
                int sel = (int)SendMessageW(comboType, CB_GETCURSEL, 0, 0);
                saved.entry.dataType = saved.savedType = static_cast<DataType>(sel);

                // 3) read the value (so saved.entry.value is populated)
                switch (saved.entry.dataType)
                {
                case DATA_BYTE:
                {
                    uint8_t v = 0;
                    ReadProcessMemory(g_hTargetProcess, (LPCVOID)saved.entry.address, &v, sizeof(v), nullptr);
                    saved.entry.value.valByte = v;
                } break;
                case DATA_2BYTE:
                {
                    uint16_t v = 0;
                    ReadProcessMemory(g_hTargetProcess, (LPCVOID)saved.entry.address, &v, sizeof(v), nullptr);
                    saved.entry.value.val2Byte = v;
                } break;
                case DATA_4BYTE:
                {
                    uint32_t v = 0;
                    ReadProcessMemory(g_hTargetProcess, (LPCVOID)saved.entry.address, &v, sizeof(v), nullptr);
                    saved.entry.value.val4Byte = v;
                } break;
                case DATA_8BYTE:
                {
                    uint64_t v = 0;
                    ReadProcessMemory(g_hTargetProcess, (LPCVOID)saved.entry.address, &v, sizeof(v), nullptr);
                    saved.entry.value.val8Byte = v;
                } break;
                case DATA_FLOAT:
                {
                    float f = 0.0f;
                    ReadProcessMemory(g_hTargetProcess, (LPCVOID)saved.entry.address, &f, sizeof(f), nullptr);
                    saved.entry.value.valFloat = f;
                } break;
                case DATA_DOUBLE:
                {
                    double d = 0.0;
                    ReadProcessMemory(g_hTargetProcess, (LPCVOID)saved.entry.address, &d, sizeof(d), nullptr);
                    saved.entry.value.valDouble = d;
                } break;
                }

                // reconstruct the comma‑delimited pointer expression
                std::wstring expr = chain[0];
                for (size_t i = 1; i < chain.size(); ++i)
                    expr += L"," + chain[i];
                saved.pointerExpr = expr;

                // push into the saved list
                g_savedEntries.push_back(saved);
                AppendSavedAddress(saved);
            }
        }

        // catch Delete key on selected row
        if (pnmh->hwndFrom == lv && pnmh->code == LVN_KEYDOWN)
        {
            LPNMLVKEYDOWN kd = (LPNMLVKEYDOWN)lParam;
            if (kd->wVKey == VK_DELETE)
                DeleteSelectedChains();
        }
    }
    break;

    case WM_TIMER:
        if (wParam == IDT_PTRTABLE_UPDATE) {
            RefreshPointerValues();
        }
        break;

    case WM_DESTROY:
        KillTimer(hwnd, IDT_PTRTABLE_UPDATE);
        DestroyWindow(lv);
        DestroyWindow(btnSave);
        DestroyWindow(comboType);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// — Type Conversion
std::wstring DataTypeToString(DataType dt)
{
    switch (dt)
    {
    case DATA_BYTE:   return L"Byte";
    case DATA_2BYTE:  return L"2 Byte";
    case DATA_4BYTE:  return L"4 Byte";
    case DATA_FLOAT:  return L"Float";
    case DATA_DOUBLE: return L"Double";
    case DATA_8BYTE:  return L"8 Byte";
    default:          return L"Unknown";
    }
}

// — B2D Scanner
struct PointerScanParams {
    uintptr_t baseAddr;
    uintptr_t dynamicAddr;
    int       maxDepth;
};

struct BFSNode {
    uintptr_t                 currentPtr;
    int                       depthUsed;
    std::vector<DWORD_PTR>    usedOffsets;
};

static char GetHighHexDigit(uintptr_t v)
{
    // Extract the top‑nibble of the most significant byte
    int bits = (sizeof(v) * 8 - 4);
    return char((v >> bits) & 0xF);
}

static int GetHexDigitCount(uintptr_t v)
{
    int count = 0;
    do { ++count; v >>= 4; } while (v);
    return count;
}

static std::vector<std::wstring> splitPointerExpr(const std::wstring& line) {
    std::vector<std::wstring> parts;
    std::wistringstream ss(line);
    std::wstring tok;
    while (std::getline(ss, tok, L',')) {
        parts.push_back(trim(tok));
    }
    return parts;
}

// — B2D Scanner - Unreal Engine Addition
static std::vector<std::wstring> ParseNames(const std::wstring& log)
{
    std::vector<std::wstring> out;
    std::wistringstream iss(log);
    std::wstring line;
    const std::wstring clsTag = L"Generating Class ";
    const std::wstring strTag = L"Generating Struct ";
    while (std::getline(iss, line))
    {
        if (line.rfind(clsTag, 0) == 0)
            out.push_back(line.substr(clsTag.size()));
        else if (line.rfind(strTag, 0) == 0)
            out.push_back(line.substr(strTag.size()));
    }
    return out;
}

static std::wstring GetUObjectName(uintptr_t objPtr)
{
    if (!objPtr) return L"";

    // Make sure we've calibrated. If not, default to 0x10 (for UE4.23+).
    uintptr_t off = g_nameFieldOffset ? g_nameFieldOffset : 0x10;
    uint32_t idx = 0, num = 0;
    ReadProcessMemory(g_hTargetProcess,
        (LPCVOID)(objPtr + off),
        &idx, sizeof(idx), nullptr);
    ReadProcessMemory(g_hTargetProcess,
        (LPCVOID)(objPtr + off + sizeof(uint32_t)),
        &num, sizeof(num), nullptr);

    std::wstring s = GetFNameString(g_hTargetProcess, idx);
    if (num) s += L"_" + std::to_wstring(num);
    auto pos = s.find_last_of(L'_');
    if (pos != std::wstring::npos) {
        bool allDigits = true;
        for (size_t i = pos + 1; i < s.size(); ++i) {
            if (!iswdigit(s[i])) { allDigits = false; break; }
        }
        if (allDigits)
            s.resize(pos);
    }
    return s;
}

LRESULT CALLBACK AutoOffsetsProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HWND lv = nullptr;

    switch (message)
    {
    case WM_CREATE:
    {
        // Create the ListView
        lv = CreateWindowExW(
            0, WC_LISTVIEW, nullptr,
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            10, 10, 400, 228,
            hDlg, (HMENU)1001,
            GetModuleHandleW(NULL), nullptr
        );
        ListView_SetExtendedListViewStyle(lv,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

        // Insert columns
        LVCOLUMNW col = { LVCF_TEXT | LVCF_WIDTH };
        col.cx = 62;  col.pszText = const_cast<LPWSTR>(L"Offset");
        ListView_InsertColumn(lv, 0, &col);
        col.cx = 120; col.pszText = const_cast<LPWSTR>(L"Address");
        ListView_InsertColumn(lv, 1, &col);
        col.cx = 200; col.pszText = const_cast<LPWSTR>(L"Description");
        ListView_InsertColumn(lv, 2, &col);

        // Populate rows
        for (int i = 0; i < (int)g_autoOffsets.size(); ++i)
        {
            uint64_t off = g_autoOffsets[i].first;
            uint64_t addr = g_autoOffsets[i].second;

            // Column 0: "+Offset"
            wchar_t buf0[32];
            swprintf(buf0, 32, L"+%llX", (unsigned long long)off);
            LVITEMW it = { LVIF_TEXT, i, 0, 0, 0, buf0 };
            ListView_InsertItem(lv, &it);

            // Column 1: "0xAddress"
            wchar_t buf1[32];
            swprintf(buf1, 32, L"0x%llX", (unsigned long long)addr);
            ListView_SetItemText(lv, i, 1, buf1);

            // Column 2: Description via name lookup
            std::wstring name = GetUObjectName(addr);
            if (name.empty()) name = L"<unknown>";
            ListView_SetItemText(lv, i, 2, const_cast<LPWSTR>(name.c_str()));
        }

        return 0;
    }

    case WM_NOTIFY:
    {
        auto* nm = reinterpret_cast<NMHDR*>(lParam);
        // Check for double‑click in our ListView
        if (nm->hwndFrom == lv && nm->code == NM_DBLCLK)
        {
            int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
            if (sel >= 0 && sel < (int)g_autoOffsets.size())
            {
                // Clear existing offsets list and add this one
                SendMessageW(g_hListOffsets, LB_RESETCONTENT, 0, 0);
                wchar_t buf[32];
                swprintf(buf, 32, L"%llX",
                    (unsigned long long)g_autoOffsets[sel].first);
                SendMessageW(g_hListOffsets, LB_ADDSTRING, 0, (LPARAM)buf);
            }
            DestroyWindow(hDlg);
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hDlg, message, wParam, lParam);
}

void ShowAutoOffsetsDialog(HWND hParent, uintptr_t worldPtr)
{
    uintptr_t basePtr = 0;
    if (!ReadProcessMemory(g_hTargetProcess,
        (LPCVOID)worldPtr,
        &basePtr,
        sizeof(basePtr),
        nullptr))
    {
        Log(L"Error: could not read UWorld pointer\r\n");
        return;
    }

    int baseDigits = GetHexDigitCount(basePtr);
    g_basePtrForDialog = basePtr;

    if (!g_nameFieldOffset)
    {
        uintptr_t testObj = 0;
        ReadProcessMemory(g_hTargetProcess,
            (LPCVOID)(basePtr + 0x30),
            &testObj,
            sizeof(testObj),
            nullptr);

        // try both candidate offsets:
        for (uintptr_t tryOff : { (uintptr_t)0x10, (uintptr_t)0x18 })
        {
            uint32_t idx = 0, num = 0;
            ReadProcessMemory(g_hTargetProcess,
                (LPCVOID)(testObj + tryOff),
                &idx, sizeof(idx), nullptr);
            ReadProcessMemory(g_hTargetProcess,
                (LPCVOID)(testObj + tryOff + 4),
                &num, sizeof(num), nullptr);

            std::wstring name = GetFNameString(g_hTargetProcess, idx);
            if (name == L"PersistentLevel")
            {
                g_nameFieldOffset = tryOff;
                break;
            }
        }

        if (!g_nameFieldOffset)
            Log(L"Failed to auto‑detect FName offset!\r\n");
    }

    g_autoOffsets.clear();
    constexpr uintptr_t START = 0x30, END = 0x200;
    for (uintptr_t off = START; off < END; off += sizeof(uintptr_t))
    {
        uintptr_t val = 0;
        if (!ReadProcessMemory(g_hTargetProcess,
            (LPCVOID)(basePtr + off),
            &val,
            sizeof(val),
            nullptr) || !val)
        {
            continue;
        }

        if (GetHexDigitCount(val) != baseDigits)
            continue;

        g_autoOffsets.emplace_back(off, val);
    }

    {
        wchar_t baseBuf[32];
        swprintf(baseBuf, 32, L"%llX", (unsigned long long)basePtr);
        std::wstring baseHex(baseBuf);

        constexpr size_t PREFIX_LEN = 3;
        size_t actualLen = (baseHex.size() < PREFIX_LEN) ? baseHex.size() : PREFIX_LEN;
        std::wstring prefix = baseHex.substr(0, actualLen);

        g_autoOffsets.erase(
            std::remove_if(
                g_autoOffsets.begin(),
                g_autoOffsets.end(),
                [&](const std::pair<uintptr_t, uintptr_t>& p) {
            wchar_t valBuf[32];
            swprintf(valBuf, 32, L"%llX", (unsigned long long)p.second);
            return std::wstring(valBuf).rfind(prefix, 0) != 0;
        }
            ),
            g_autoOffsets.end()
        );
    }

    // 4) Register the popup class (once)
    const wchar_t* cls = L"AutoOffsetPicker";
    static bool reg = false;
    if (!reg)
    {
        WNDCLASSW wc{ 0 };
        wc.lpfnWndProc = AutoOffsetsProc;
        wc.lpszClassName = cls;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassW(&wc);
        reg = true;
    }

    RECT parentRect;
    GetWindowRect(hParent, &parentRect);
    const int W = 430, H = 280;
    int X = parentRect.left + ((parentRect.right - parentRect.left) - W) / 2;
    int Y = parentRect.top + ((parentRect.bottom - parentRect.top) - H) / 2;

    HWND dlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME, cls, L"Base Offsets..",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        X, Y, W, H, hParent, nullptr,
        GetModuleHandleW(NULL), nullptr
    );
    ShowWindow(dlg, SW_SHOW);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

static bool SafeReadPtr(uintptr_t addr, DWORD_PTR* out)
{
    return !!ReadProcessMemory(g_hTargetProcess,
        (LPCVOID)addr,
        out,
        sizeof(*out),
        nullptr);
}

static uintptr_t ParsePointerAddress(const std::wstring& s)
{
    size_t p = s.find(L".exe+");
    if (p != std::wstring::npos) {
        std::wstring modName = s.substr(0, p + 4);
        std::wstring offStr = s.substr(p + 5);
        uintptr_t offset = std::wcstoull(offStr.c_str(), nullptr, 16);
        uintptr_t base = GetRemoteModuleBaseAddressByName(g_targetProcessId, modName);
        if (!base) return 0;
        uintptr_t raw = base + offset;
        uintptr_t val = 0;
        return SafeReadPtr(raw, &val) ? val : 0;
    }

    if (_wcsnicmp(s.c_str(), L"7F", 2) == 0) {
        uintptr_t raw = std::wcstoull(s.c_str(), nullptr, 16);
        uintptr_t val = 0;
        return SafeReadPtr(raw, &val) ? val : 0;
    }

    return std::wcstoull(s.c_str(), nullptr, 16);
}

static bool IsAllowedAddress(uintptr_t v, const std::vector<char>& allowedHighDigits)
{
    char high = GetHighHexDigit(v);
    return std::find(allowedHighDigits.begin(),
        allowedHighDigits.end(),
        high) != allowedHighDigits.end();
}

static std::string FormatChain(uintptr_t base,
    uintptr_t dyn,
    const std::vector<UINT_PTR>& offs)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (size_t i = 0; i < offs.size(); ++i) {
        if (i) oss << ",";
        oss << "0x" << offs[i];
    }
    return oss.str();
}

// - WinProc Helpers
static LRESULT Handle_CopyData(HWND hWnd, LPARAM lParam)
{
    PCOPYDATASTRUCT cds = (PCOPYDATASTRUCT)lParam;
    if (cds->dwData == 1 && cds->lpData) {
        LPCWSTR path = (LPCWSTR)cds->lpData;
        LoadTableFromFile(path);
    }
    return TRUE;
}

static LRESULT Handle_CtlColorStatic(WPARAM wParam, LPARAM lParam)
{
    HDC hdcStatic = (HDC)wParam;
    SetBkMode(hdcStatic, TRANSPARENT);
    return (LRESULT)(GetSysColorBrush(COLOR_WINDOW));
}

static LRESULT Handle_Create(HWND hWnd, LPARAM lParam)
{
    HMENU hMenu = CreateMenu();
    MENUITEMINFO mii = { sizeof(mii) };

    mii.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
    mii.fType = MFT_STRING;
    mii.wID = ID_MENU_ATTACH;
    mii.dwTypeData = const_cast<LPWSTR>(L"Attach");
    InsertMenuItemW(hMenu, 0, TRUE, &mii);

    mii.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
    mii.fType = MFT_STRING;
    mii.wID = ID_MENU_THREAD;
    mii.dwTypeData = const_cast<LPWSTR>(L"Inject");
    InsertMenuItemW(hMenu, 1, TRUE, &mii);

    mii.fMask = MIIM_FTYPE | MIIM_STATE | MIIM_STRING;
    mii.fType = MFT_STRING;
    mii.fState = MFS_DISABLED;
    mii.dwTypeData = const_cast<LPWSTR>(L"│");
    InsertMenuItemW(hMenu, 2, TRUE, &mii);

    mii.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
    mii.fType = MFT_STRING;
    mii.wID = ID_MENU_SETTINGS;
    mii.dwTypeData = const_cast<LPWSTR>(L"Settings");
    InsertMenuItemW(hMenu, 3, TRUE, &mii);

    mii.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
    mii.fType = MFT_STRING | MFT_RIGHTJUSTIFY;
    mii.wID = ID_MENU_PROCINFO;
    mii.dwTypeData = const_cast<LPWSTR>(L"");
    InsertMenuItemW(hMenu, 4, TRUE, &mii);

    SetMenu(hWnd, hMenu);
    DrawMenuBar(hWnd);

    {
        wchar_t fullPath[MAX_PATH] = {};
        DWORD   len = MAX_PATH;
        if (QueryFullProcessImageNameW(
            GetCurrentProcess(),
            0,
            fullPath,
            &len
        ))
        {
            wchar_t* exeName = wcsrchr(fullPath, L'\\');
            exeName = exeName ? exeName + 1 : fullPath;

            wchar_t info[128];
            swprintf(info, 128, L"%s (PID: %lu)",
                exeName,
                GetCurrentProcessId());

            MENUITEMINFO miiInfo = { sizeof(miiInfo) };
            miiInfo.fMask = MIIM_STRING;
            miiInfo.dwTypeData = info;
            SetMenuItemInfoW(hMenu, ID_MENU_PROCINFO, FALSE, &miiInfo);
            DrawMenuBar(hWnd);
        }
    }

    HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;

    g_hStaticScanStatus = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"STATIC", L"Displaying 0 values out of 0",
        WS_CHILD | WS_VISIBLE, 10, 10, 450, 25,
        hWnd, (HMENU)IDC_STATIC_SCANSTATUS, hInst, NULL
    );
    g_hProgressBar = CreateWindowExW(
        0, PROGRESS_CLASS, NULL,
        WS_CHILD | WS_VISIBLE, 10, 40, 450, 20,
        hWnd, (HMENU)IDC_PROGRESS_BAR, hInst, NULL
    );

    g_hListScanResults = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 65, 450, 235,
        hWnd, (HMENU)IDC_LIST_SCANRESULTS, hInst, NULL
    );
    ListView_SetExtendedListViewStyle(
        g_hListScanResults,
        ListView_GetExtendedListViewStyle(g_hListScanResults)
        | LVS_EX_DOUBLEBUFFER
    );
    {
        LVCOLUMN col = { LVCF_TEXT | LVCF_WIDTH };
        col.pszText = const_cast<LPWSTR>(L"Address");  col.cx = 150;
        ListView_InsertColumn(g_hListScanResults, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"Value");    col.cx = 100;
        ListView_InsertColumn(g_hListScanResults, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"Previous"); col.cx = 100;
        ListView_InsertColumn(g_hListScanResults, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"First");    col.cx = 96;
        ListView_InsertColumn(g_hListScanResults, 3, &col);
    }

    g_hListSavedAddresses = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 305, 450, 165,
        hWnd, (HMENU)IDC_LIST_SAVEDADDR, hInst, NULL
    );
    DWORD ex = ListView_GetExtendedListViewStyle(g_hListSavedAddresses);
    ListView_SetExtendedListViewStyle(
        g_hListSavedAddresses,
        ex
        | LVS_EX_CHECKBOXES
        | LVS_EX_FULLROWSELECT
        | LVS_EX_DOUBLEBUFFER
    );
    {
        LVCOLUMN col = { LVCF_TEXT | LVCF_WIDTH };
        col.pszText = const_cast<LPWSTR>(L"Freeze");     col.cx = 50;
        ListView_InsertColumn(g_hListSavedAddresses, 0, &col);
        col.pszText = const_cast<LPWSTR>(L"Description"); col.cx = 126;
        ListView_InsertColumn(g_hListSavedAddresses, 1, &col);
        col.pszText = const_cast<LPWSTR>(L"Address");    col.cx = 100;
        ListView_InsertColumn(g_hListSavedAddresses, 2, &col);
        col.pszText = const_cast<LPWSTR>(L"Type");       col.cx = 70;
        ListView_InsertColumn(g_hListSavedAddresses, 3, &col);
        col.pszText = const_cast<LPWSTR>(L"Value");      col.cx = 70;
        ListView_InsertColumn(g_hListSavedAddresses, 4, &col);
        col.pszText = const_cast<LPWSTR>(L"Del");        col.cx = 30;
        ListView_InsertColumn(g_hListSavedAddresses, 5, &col);
    }

    const int btnX = 480, btnY = 10, btnW = 100, btnH = 25, gap = 10;
    g_hBtnFirstScan = CreateWindowW(
        L"BUTTON", L"First Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX, btnY, btnW, btnH, hWnd, (HMENU)IDC_BTN_FIRSTSCAN, hInst, NULL
    );
    g_hBtnNextScan = CreateWindowW(
        L"BUTTON", L"Next Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX + 1 * (btnW + gap), btnY, btnW, btnH, hWnd, (HMENU)IDC_BTN_NEXTSCAN, hInst, NULL
    );
    g_hBtnUndoScan = CreateWindowW(
        L"BUTTON", L"Undo Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX + 2 * (btnW + gap), btnY, btnW, btnH, hWnd, (HMENU)IDC_BTN_UNDOSCAN, hInst, NULL
    );
    g_hBtnNewScan = CreateWindowW(
        L"BUTTON", L"New Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX + 3 * (btnW + gap), btnY, btnW, btnH, hWnd, (HMENU)IDC_BTN_NEWSCAN, hInst, NULL
    );

    int addY = btnY + btnH + 10 + 300 - (btnH + 10);
    HWND hBtnAddAddress = CreateWindowW(
        L"BUTTON", L"Add Address",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX, addY, btnW, btnH, hWnd, (HMENU)IDC_BTN_ADDADDRESS, hInst, NULL
    );

    const int verticalPadding = 5;
    int lblY = btnY + btnH + 10 + verticalPadding;
    HWND hLblValue = CreateWindowExW(
        0, L"STATIC", L"Value:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        btnX, lblY, 60, 20,
        hWnd, NULL, hInst, NULL
    );
    SendMessageW(hLblValue, WM_SETFONT, (WPARAM)hFont, TRUE);

    int editW = 4 * btnW + 3 * gap;
    int editY = lblY + 20;
    g_hEditValue = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        btnX, editY, editW, 25, hWnd, (HMENU)IDC_EDIT_VALUE, hInst, NULL
    );

    int comboY = editY + 25 + 5;
    const int comboW = 210, comboH = 100;
    g_hComboValueType = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        btnX, comboY, comboW, comboH, hWnd, (HMENU)IDC_COMBO_VALUETYPE, hInst, NULL
    );
    for (auto* s : { L"Byte",L"2 Byte",L"4 Byte",L"8 Byte",L"Float",L"Double" })
        SendMessageW(g_hComboValueType, CB_ADDSTRING, 0, (LPARAM)s);
    SendMessageW(g_hComboValueType, CB_SETCURSEL, 2, 0);

    HWND hComboSearch = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        btnX + comboW + gap, comboY, comboW, comboH, hWnd, (HMENU)IDC_COMBO_SEARCHMODE, hInst, NULL
    );
    for (auto* s : { L"Exact Value",L"Bigger Than",L"Smaller Than",
                     L"Value Between", L"Unknown Initial Value" })
        SendMessageW(hComboSearch, CB_ADDSTRING, 0, (LPARAM)s);
    SendMessageW(hComboSearch, CB_SETCURSEL, 0, 0);

    int frameY = comboY + comboH - 65;
    HWND g_hChainFrame = CreateWindowExW(
        0, L"STATIC", NULL,
        WS_CHILD | WS_VISIBLE | SS_BLACKFRAME,
        btnX, frameY, editW, 160,
        hWnd, (HMENU)IDC_CHAIN_FRAME, hInst, NULL
    );
    SendMessageW(g_hChainFrame, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    SIZE hdrSz;
    {
        HDC hdc = GetDC(hWnd);
        HFONT oldF = (HFONT)SelectObject(hdc, hSmallFont);
        GetTextExtentPoint32W(hdc, L"Pointer Scanner", lstrlenW(L"Pointer Scanner"), &hdrSz);
        SelectObject(hdc, oldF);
        ReleaseDC(hWnd, hdc);
    }

    int textY = frameY - (hdrSz.cy / 2);
    HWND hLblBase = CreateWindowW(
        L"STATIC", L"Pointer Scanner",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        btnX + 8, textY,
        hdrSz.cx, hdrSz.cy,
        hWnd, NULL, hInst, NULL
    );
    SendMessageW(hLblBase, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    int groupX = btnX + 256;
    int margin = 4;
    int offsX = groupX + margin;

    HDC hdc2 = GetDC(hWnd);
    HFONT oldF2 = (HFONT)SelectObject(hdc2, hSmallFont);
    GetTextExtentPoint32W(
        hdc2,
        L"Positional Offsets",
        lstrlenW(L"Positional Offsets"),
        &hdrSz
    );
    SelectObject(hdc2, oldF2);
    ReleaseDC(hWnd, hdc2);

    HWND hLblOffsets = CreateWindowW(
        L"STATIC", L"Positional Offsets",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        offsX, textY,
        hdrSz.cx, hdrSz.cy,
        hWnd, NULL, hInst, NULL
    );
    SendMessageW(hLblOffsets, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    int newAddY = frameY + 160 + 10;
    SetWindowPos(hBtnAddAddress, NULL, btnX, newAddY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    int labelX = btnX + 8;
    int labelW = 75;
    int labelGap = 1;
    int editX = labelX + labelW + labelGap;

    CreateWindowW(L"STATIC", L"Base Addr:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        labelX, frameY + 18, labelW, 20,
        hWnd, (HMENU)IDC_STATIC_BASE_ADDRESS, hInst, NULL);

    g_hEditBaseAddress = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        editX, frameY + 16, 160, 24,
        hWnd, (HMENU)IDC_EDIT_BASE_ADDRESS, hInst, NULL);
    g_oldBaseAddrProc = (WNDPROC)SetWindowLongPtrW(
        g_hEditBaseAddress,
        GWLP_WNDPROC,
        (LONG_PTR)BaseAddrEditProc
    );

    CreateWindowW(L"STATIC", L"Dyn Addr:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        labelX, frameY + 16 + 32, labelW, 20,
        hWnd, (HMENU)IDC_STATIC_DYNAMIC_ADDRESS, hInst, NULL);

    g_hDynamicAddressEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        editX, frameY + 14 + 32, 160, 24,
        hWnd, (HMENU)IDC_EDIT_DYNAMIC_ADDRESS, hInst, NULL);

    CreateWindowW(L"STATIC", L"Max Depth:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        labelX, frameY + 16 + 62, labelW, 20,
        hWnd, (HMENU)IDC_STATIC_MAXDEPTH, hInst, NULL);

    for (int id : { IDC_STATIC_BASE_ADDRESS,
        IDC_STATIC_DYNAMIC_ADDRESS,
        IDC_STATIC_MAXDEPTH })
    {
        HWND hLbl = GetDlgItem(hWnd, id);
        SendMessageW(hLbl, WM_SETFONT, (WPARAM)hHeaderFont, TRUE);
    }

    g_hEditMaxDepth = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"3",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        editX, frameY + 15 + 60, 40, 24,
        hWnd, (HMENU)IDC_EDIT_MAXDEPTH, hInst, NULL);

    // Checkbox: Scan From Saved File
    HWND hChkSaved = CreateWindowW(
        L"BUTTON", L"Scan From File",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        editX + 55,
        frameY + 17 + 60,
        110, 20,
        hWnd, (HMENU)IDC_CHECK_SCAN_SAVED_FILE, hInst, NULL);
    SendMessageW(hChkSaved, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    g_hBtnPointerScan = CreateWindowW(
        L"BUTTON", L"Scan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        editX - 60, frameY + 116, 90, 28,
        hWnd, (HMENU)IDC_BTN_POINTERSCAN, hInst, NULL);
    SendMessageW(g_hBtnPointerScan, WM_SETFONT, (WPARAM)hHeaderFont, TRUE);

    g_hBtnViewPTRs = CreateWindowW(
        L"BUTTON", L"View PTRs",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        editX + 50, frameY + 116,
        90, 28,
        hWnd, (HMENU)IDC_BTN_VIEWPTRS, hInst, NULL);
    SendMessageW(g_hBtnViewPTRs, WM_SETFONT, (WPARAM)hHeaderFont, TRUE);

    int groupY = frameY + 1;
    int groupW = 167;
    int groupH = 153;

    {
        const int margin = 4;
        const int titleH = 16;
        const int listX = groupX + margin;
        const int listY = groupY + margin + titleH - 5;
        const int listW = groupW - margin * 2;
        const int listH = 70 + 17;
        g_hListOffsets = CreateWindowExW(
            WS_EX_CLIENTEDGE, WC_LISTBOX, L"",
            WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
            listX, listY, listW, listH,
            hWnd, (HMENU)IDC_LIST_OFFSETS, hInst, NULL
        );
        g_oldOffsetsProc = (WNDPROC)SetWindowLongPtrW(
            g_hListOffsets,
            GWLP_WNDPROC,
            (LONG_PTR)OffsetsListProc
        );

        const int editH = 24;
        const int editY = listY + listH + margin - 4;
        g_hEditOffsetEntry = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            listX, editY, listW, editH,
            hWnd, (HMENU)IDC_EDIT_OFFSETNEW, hInst, NULL
        );

        g_oldOffsetEditProc = (WNDPROC)SetWindowLongPtrW(
            g_hEditOffsetEntry,
            GWLP_WNDPROC,
            (LONG_PTR)EditOffsetProc
        );

        const int btnH = 22;
        const int btnW = 50;
        const int btnGap = 5;
        const int btnY2 = editY + editH + 4;
        g_hBtnAddOffset = CreateWindowW(
            L"BUTTON", L"Add",
            WS_CHILD | WS_VISIBLE,
            listX, btnY2, btnW, btnH,
            hWnd, (HMENU)IDC_BTN_OFFSET_ADD, hInst, NULL
        );
        g_hBtnRemoveOffset = CreateWindowW(
            L"BUTTON", L"Del",
            WS_CHILD | WS_VISIBLE,
            listX + btnW + btnGap, btnY2, btnW, btnH,
            hWnd, (HMENU)IDC_BTN_OFFSET_DEL, hInst, NULL
        );
        g_hBtnAutoOffset = CreateWindowW(
            L"BUTTON", L"Auto",
            WS_CHILD | WS_VISIBLE,
            listX + 2 * (btnW + btnGap),
            btnY2, btnW, btnH,
            hWnd, (HMENU)IDC_BTN_OFFSET_AUTO, hInst, NULL
        );
        EnableWindow(g_hBtnAutoOffset, FALSE);
        SendMessageW(g_hBtnAddOffset, WM_SETFONT, (WPARAM)hHeaderFont, TRUE);
        SendMessageW(g_hBtnRemoveOffset, WM_SETFONT, (WPARAM)hHeaderFont, TRUE);
        SendMessageW(g_hBtnAutoOffset, WM_SETFONT, (WPARAM)hHeaderFont, TRUE);
    }

    const int subGap = 5;
    HWND hBtnSaveTable = CreateWindowW(
        L"BUTTON", L"Save Table",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX, newAddY + (btnH + subGap) * 1, btnW, btnH,
        hWnd, (HMENU)IDC_BTN_SAVETABLE, hInst, NULL
    );
    HWND hBtnLoadTable = CreateWindowW(
        L"BUTTON", L"Load Table",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX, newAddY + (btnH + subGap) * 2, btnW, btnH,
        hWnd, (HMENU)IDC_BTN_LOADTABLE, hInst, NULL
    );
    HWND hBtnSaveCT = CreateWindowW(
        L"BUTTON", L"Save as .CT",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX, newAddY + (btnH + subGap) * 3, btnW, btnH,
        hWnd, (HMENU)IDC_BTN_SAVECT, hInst, NULL
    );

    const int exitGap = 20;
    int exitY = newAddY + (btnH + subGap) * 4 + exitGap;

    HWND hBtnExit = CreateWindowW(
        L"BUTTON", L"Exit",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON | BS_FLAT,
        btnX, exitY, btnW, btnH,
        hWnd, (HMENU)IDC_BTN_EXIT, hInst, NULL
    );

    int logX = btnX + btnW + gap;
    int logY = newAddY;
    int logW = 320, logH = 165;

    g_hOutputLog = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"MemRE Logs:\r\n\r\n",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY | ES_NOHIDESEL,
        logX, logY, logW, logH,
        hWnd, (HMENU)IDC_EDIT_LOG, hInst, NULL
    );
    g_oldLogProc = (WNDPROC)SetWindowLongPtrW(g_hOutputLog, GWLP_WNDPROC, (LONG_PTR)LogEditProc);


    HWND ctrls[] = {
        (HWND)g_hEditValue, g_hComboValueType, hComboSearch,
        g_hBtnFirstScan, g_hBtnNextScan, g_hBtnUndoScan, g_hBtnNewScan,
        hBtnAddAddress, hBtnSaveTable, hBtnLoadTable, hBtnSaveCT,
        hBtnExit, g_hOutputLog, g_hEditBaseAddress, g_hDynamicAddressEdit,
        g_hEditMaxDepth, g_hEditOffsetEntry, g_hBtnAutoOffset, g_hBtnViewPTRs
    };
    for (HWND ctrl : ctrls)
        SendMessageW(ctrl, WM_SETFONT, (WPARAM)hFont, TRUE);

    SendMessageW(g_hListOffsets, WM_SETFONT, (WPARAM)hFont, TRUE);
    SetWindowTheme(g_hListScanResults, L"Explorer", NULL);
    SetWindowTheme(g_hListSavedAddresses, L"Explorer", NULL);
    SetTimer(hWnd, IDT_UPDATE_TIMER, UPDATE_INTERVAL_MS, NULL);
    UpdateScanButtons(false);

    return 0;
}

static LRESULT Handle_Timer(HWND hWnd)
{
    if (g_hPointerScanThread &&
        WaitForSingleObject(g_hPointerScanThread, 0) == WAIT_OBJECT_0)
    {
        CloseHandle(g_hPointerScanThread);
        g_hPointerScanThread = nullptr;
        g_isPointerScanning = false;
        SetWindowTextW(g_hBtnPointerScan, L"Scan");

        SendMessage(g_hProgressBar, PBM_SETMARQUEE, FALSE, 0);
        {
            LONG_PTR style = GetWindowLongPtr(g_hProgressBar, GWL_STYLE);
            SetWindowLongPtr(
                g_hProgressBar,
                GWL_STYLE,
                style & ~PBS_MARQUEE
            );
        }
        UpdateWindow(g_hProgressBar);

        EnableWindow(g_hEditBaseAddress, TRUE);
        EnableWindow(g_hDynamicAddressEdit, TRUE);
        EnableWindow(g_hEditMaxDepth, TRUE);
        EnableWindow(g_hListOffsets, TRUE);
        EnableWindow(g_hBtnAddOffset, TRUE);
        EnableWindow(g_hBtnRemoveOffset, TRUE);
        EnableWindow(g_hBtnAutoOffset, TRUE);
        EnableWindow(g_hBtnViewPTRs, TRUE);
        EnableWindow(GetDlgItem(hWnd, IDC_CHECK_SCAN_SAVED_FILE), TRUE);
    }

    if (!g_savedEntries.empty()) {
        ResolvePendingSavedEntries();
    }
    if (!g_lastDisplayedEntries.empty())
    {
        HANDLE hProcess = g_hTargetProcess;
        for (size_t i = 0; i < g_lastDisplayedEntries.size(); i++)
        {
            ScanEntry oldCurrent = g_lastDisplayedEntries[i];
            ScanEntry newEntry = oldCurrent;
            bool updated = false;
            if (newEntry.dataType == DATA_BYTE)
            {
                uint8_t val = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)newEntry.address, &val, sizeof(val), NULL))
                    if (val != oldCurrent.value.valByte) { newEntry.value.valByte = val; updated = true; }
            }
            else if (newEntry.dataType == DATA_2BYTE)
            {
                uint16_t val = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)newEntry.address, &val, sizeof(val), NULL))
                    if (val != oldCurrent.value.val2Byte) { newEntry.value.val2Byte = val; updated = true; }
            }
            else if (newEntry.dataType == DATA_4BYTE)
            {
                uint32_t val = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)newEntry.address, &val, sizeof(val), NULL))
                    if (val != oldCurrent.value.val4Byte) { newEntry.value.val4Byte = val; updated = true; }
            }
            else if (newEntry.dataType == DATA_8BYTE)
            {
                uint64_t val = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)newEntry.address, &val, sizeof(val), NULL))
                    if (val != oldCurrent.value.val8Byte) { newEntry.value.val8Byte = val; updated = true; }
            }
            else if (newEntry.dataType == DATA_FLOAT)
            {
                float val = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)newEntry.address, &val, sizeof(val), NULL))
                    if (fabs(val - oldCurrent.value.valFloat) > epsilon_float) { newEntry.value.valFloat = val; updated = true; }
            }
            else if (newEntry.dataType == DATA_DOUBLE)
            {
                double val = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)newEntry.address, &val, sizeof(val), NULL))
                    if (fabs(val - oldCurrent.value.valDouble) > epsilon_double) { newEntry.value.valDouble = val; updated = true; }
            }
            if (updated)
            {
                wchar_t currStr[64] = { 0 };
                switch (newEntry.dataType)
                {
                case DATA_BYTE:   swprintf(currStr, 64, L"%u", newEntry.value.valByte); break;
                case DATA_2BYTE:  swprintf(currStr, 64, L"%u", newEntry.value.val2Byte); break;
                case DATA_4BYTE:  swprintf(currStr, 64, L"%u", newEntry.value.val4Byte); break;
                case DATA_8BYTE:  swprintf(currStr, 64, L"%llu", newEntry.value.val8Byte); break;
                case DATA_FLOAT:  swprintf(currStr, 64, L"%.4f", newEntry.value.valFloat); break;
                case DATA_DOUBLE: swprintf(currStr, 64, L"%.4f", newEntry.value.valDouble); break;
                default: swprintf(currStr, 64, L"Unknown"); break;
                }
                ListView_SetItemText(g_hListScanResults, (int)i, 1, currStr);
                g_itemChanged[i] = true;
                g_lastDisplayedEntries[i] = newEntry;
            }
        }
        InvalidateRect(g_hListScanResults, NULL, TRUE);
    }
    if (g_isAttached)
    {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(g_hTargetProcess, &exitCode) && exitCode != STILL_ACTIVE)
        {
            DWORD oldPID = g_targetProcessId;
            CloseHandle(g_hTargetProcess);

            g_hTargetProcess = GetCurrentProcess();
            g_targetProcessId = GetCurrentProcessId();
            g_isAttached = false;

            HMENU hMenu = GetMenu(hWnd);
            MENUITEMINFO mii = { sizeof(mii) };
            mii.fMask = MIIM_STRING;
            mii.dwTypeData = const_cast<LPWSTR>(L"Attach");
            SetMenuItemInfoW(hMenu, ID_MENU_ATTACH, FALSE, &mii);

            WCHAR myPath[MAX_PATH];
            GetModuleFileNameW(NULL, myPath, MAX_PATH);
            WCHAR* myExe = wcsrchr(myPath, L'\\');
            myExe = myExe ? myExe + 1 : myPath;
            WCHAR info[128];
            swprintf_s(info, _countof(info), L"%s (PID: %lu)", myExe, g_targetProcessId);
            MENUITEMINFO miiInfo = { sizeof(miiInfo) };
            miiInfo.fMask = MIIM_STRING;
            miiInfo.dwTypeData = info;
            SetMenuItemInfoW(hMenu, ID_MENU_PROCINFO, FALSE, &miiInfo);

            DrawMenuBar(hWnd);

            std::wstring msg = L"Process (PID: " + std::to_wstring(oldPID) + L") exited, detached.\r\n\r\n";
            Log(msg.c_str());

            SendMessageW(g_hWndMain, WM_COMMAND, MAKEWPARAM(IDC_BTN_NEWSCAN, 0), 0);
        }
    }
    {
        HANDLE hProcess = g_hTargetProcess;
        for (size_t i = 0; i < g_savedEntries.size(); i++)
        {
            SavedEntry& saved = g_savedEntries[i];
            wchar_t newValueStr[64] = { 0 };
            switch (saved.savedType)
            {
            case DATA_BYTE:
            {
                uint8_t memVal = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)saved.entry.address, &memVal, sizeof(memVal), NULL))
                {
                    if (saved.freeze) { WriteProcessMemory(hProcess, (LPVOID)saved.entry.address, &saved.entry.value.valByte, sizeof(uint8_t), NULL); memVal = saved.entry.value.valByte; }
                    else if (memVal != saved.entry.value.valByte) { saved.entry.value.valByte = memVal; }
                    swprintf(newValueStr, 64, L"%u", memVal);
                }
            }
            break;
            case DATA_2BYTE:
            {
                uint16_t memVal = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)saved.entry.address, &memVal, sizeof(memVal), NULL))
                {
                    if (saved.freeze) { WriteProcessMemory(hProcess, (LPVOID)saved.entry.address, &saved.entry.value.val2Byte, sizeof(uint16_t), NULL); memVal = saved.entry.value.val2Byte; }
                    else if (memVal != saved.entry.value.val2Byte) { saved.entry.value.val2Byte = memVal; }
                    swprintf(newValueStr, 64, L"%u", memVal);
                }
            }
            break;
            case DATA_4BYTE:
            {
                uint32_t memVal = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)saved.entry.address, &memVal, sizeof(memVal), NULL))
                {
                    if (saved.freeze) { WriteProcessMemory(hProcess, (LPVOID)saved.entry.address, &saved.entry.value.val4Byte, sizeof(uint32_t), NULL); memVal = saved.entry.value.val4Byte; }
                    else if (memVal != saved.entry.value.val4Byte) { saved.entry.value.val4Byte = memVal; }
                    swprintf(newValueStr, 64, L"%u", memVal);
                }
            }
            break;
            case DATA_8BYTE:
            {
                uint64_t memVal = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)saved.entry.address, &memVal, sizeof(memVal), NULL))
                {
                    if (saved.freeze) { WriteProcessMemory(hProcess, (LPVOID)saved.entry.address, &saved.entry.value.val8Byte, sizeof(uint64_t), NULL); memVal = saved.entry.value.val8Byte; }
                    else if (memVal != saved.entry.value.val8Byte) { saved.entry.value.val8Byte = memVal; }
                    swprintf(newValueStr, 64, L"%llu", memVal);
                }
            }
            break;
            case DATA_FLOAT:
            {
                float memVal = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)saved.entry.address, &memVal, sizeof(memVal), NULL))
                {
                    if (saved.freeze) { WriteProcessMemory(hProcess, (LPVOID)saved.entry.address, &saved.entry.value.valFloat, sizeof(float), NULL); memVal = saved.entry.value.valFloat; }
                    else if (fabs(memVal - saved.entry.value.valFloat) > epsilon_float) { saved.entry.value.valFloat = memVal; }
                    swprintf(newValueStr, 64, L"%.4f", memVal);
                }
            }
            break;
            case DATA_DOUBLE:
            {
                double memVal = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)saved.entry.address, &memVal, sizeof(memVal), NULL))
                {
                    if (saved.freeze) { WriteProcessMemory(hProcess, (LPVOID)saved.entry.address, &saved.entry.value.valDouble, sizeof(double), NULL); memVal = saved.entry.value.valDouble; }
                    else if (fabs(memVal - saved.entry.value.valDouble) > epsilon_double) { saved.entry.value.valDouble = memVal; }
                    swprintf(newValueStr, 64, L"%.4f", memVal);
                }
            }
            break;
            default:
                swprintf(newValueStr, 64, L"Unknown");
                break;
            }
            ListView_SetItemText(g_hListSavedAddresses, (int)i, 4, newValueStr);
        }
    }
    return 0;
}

static LRESULT Handle_Notify(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    NMHDR* pnmh = (NMHDR*)lParam;

    if (pnmh->idFrom == IDC_LIST_SCANRESULTS)
    {
        if (pnmh->code == NM_CUSTOMDRAW)
        {
            LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lParam;
            switch (cd->nmcd.dwDrawStage)
            {
            case CDDS_PREPAINT:
                return CDRF_NOTIFYITEMDRAW;
            case CDDS_ITEMPREPAINT:
            {
                int idx = (int)cd->nmcd.dwItemSpec;
                if (idx >= 0 && idx < (int)g_itemChanged.size() && g_itemChanged[idx])
                    cd->clrText = RGB(255, 0, 0);
            }
            return CDRF_DODEFAULT;
            default:
                return CDRF_DODEFAULT;
            }
        }
        else if (pnmh->code == NM_DBLCLK)
        {
            LPNMITEMACTIVATE act = (LPNMITEMACTIVATE)lParam;
            int iItem = act->iItem;
            if (iItem >= 0 && iItem < (int)g_lastDisplayedEntries.size())
            {
                SavedEntry saved{};
                saved.freeze = false;
                saved.entry = g_lastDisplayedEntries[iItem];
                saved.savedType = g_lastDisplayedEntries[iItem].dataType;
                g_savedEntries.push_back(saved);
                AppendSavedAddress(saved);
            }
        }
    }
    else if (pnmh->idFrom == IDC_LIST_SAVEDADDR)
    {
        if (pnmh->code == LVN_ITEMCHANGED)
        {
            NMLISTVIEW* lvl = (NMLISTVIEW*)lParam;
            if (lvl->uChanged & LVIF_STATE)
            {
                if (lvl->uNewState & LVIS_SELECTED)
                {
                    g_pointerScanTargetIndex = lvl->iItem;

                    SavedEntry& s = g_savedEntries[g_pointerScanTargetIndex];
                    wchar_t buf[32];
                    swprintf(buf, 32, L"%llX", (unsigned long long)s.entry.address);
                    SetWindowTextW(g_hDynamicAddressEdit, buf);
                }
                BOOL chk = ListView_GetCheckState(g_hListSavedAddresses, lvl->iItem);
                g_savedEntries[lvl->iItem].freeze = (chk != FALSE);

                if (lvl->uNewState & LVIS_SELECTED)
                {
                    int baseLen = GetWindowTextLengthW(g_hEditBaseAddress);
                    if (baseLen > 0)
                    {
                        SavedEntry& s = g_savedEntries[lvl->iItem];
                        wchar_t buf[32];
                        swprintf(buf, 32, L"%llX", (unsigned long long)s.entry.address);
                        SetWindowTextW(g_hDynamicAddressEdit, buf);
                    }
                }
            }
        }
        else if (pnmh->code == NM_CLICK)
        {
            LPNMITEMACTIVATE act = (LPNMITEMACTIVATE)lParam;
            RECT rcDel;
            if (ListView_GetSubItemRect(g_hListSavedAddresses, act->iItem, 5, LVIR_BOUNDS, &rcDel))
            {
                if (act->ptAction.x >= rcDel.left && act->ptAction.x <= rcDel.right)
                {
                    g_savedEntries.erase(g_savedEntries.begin() + act->iItem);
                    ListView_DeleteItem(g_hListSavedAddresses, act->iItem);
                    AdjustSavedListColumns();
                }
            }
        }
        else if (pnmh->code == NM_DBLCLK)
        {
            LPNMITEMACTIVATE act = (LPNMITEMACTIVATE)lParam;
            int iItem = act->iItem;
            if (iItem < 0 || iItem >= (int)g_savedEntries.size())
                return 0;

            POINT pt = act->ptAction;
            RECT itemRc;
            ListView_GetItemRect(g_hListSavedAddresses, iItem, &itemRc, LVIR_BOUNDS);

            int colCount = 6;
            int x = itemRc.left;
            for (int col = 0; col < colCount; ++col)
            {
                LV_COLUMN lvc = { LVCF_WIDTH };
                ListView_GetColumn(g_hListSavedAddresses, col, &lvc);
                int colLeft = x, colRight = x + lvc.cx;

                if (pt.x >= colLeft && pt.x <= colRight)
                {
                    if (col == 2)
                    {
                        ShowEditAddressDialog(hWnd, iItem);
                    }
                    else if (col == 1 || col == 4)
                    {
                        RECT subRc;
                        if (ListView_GetSubItemRect(g_hListSavedAddresses, iItem, col, LVIR_BOUNDS, &subRc))
                        {
                            wchar_t txt[256] = { 0 };
                            ListView_GetItemText(g_hListSavedAddresses, iItem, col, txt, _countof(txt));

                            g_hSubItemEdit = CreateWindowExW(
                                WS_EX_CLIENTEDGE, L"EDIT", txt,
                                WS_CHILD | WS_BORDER | WS_VISIBLE | ES_AUTOHSCROLL,
                                subRc.left, subRc.top,
                                subRc.right - subRc.left,
                                subRc.bottom - subRc.top,
                                g_hListSavedAddresses, (HMENU)1000,
                                GetModuleHandleW(NULL), NULL
                            );
                            SubclassEditControl(g_hSubItemEdit);
                            g_editingItem = iItem;
                            g_editingSubItem = col;
                            SetFocus(g_hSubItemEdit);
                            SendMessage(g_hSubItemEdit, EM_SETSEL, 0, -1);
                        }
                    }
                    break;
                }
                x = colRight;
            }
        }
    }

    return 0;
}

static LRESULT Handle_Command(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
    int wmId = LOWORD(wParam);
    int wmEvent = HIWORD(wParam);

    if (wmId == IDC_COMBO_SEARCHMODE && wmEvent == CBN_SELCHANGE)
    {
        HWND hComboSearchMode = GetDlgItem(hWnd, IDC_COMBO_SEARCHMODE);
        LRESULT sel = SendMessage(hComboSearchMode, CB_GETCURSEL, 0, 0);
        
        if (sel >= 4 && sel <= 8)
        {
            EnableWindow(g_hEditValue, FALSE);
            SetWindowText(g_hEditValue, L"");
        }
        else
        {
            EnableWindow(g_hEditValue, TRUE);
        }
    }

    switch (wmId)
    {
    case IDC_BTN_FIRSTSCAN:
    {
        wchar_t buffer[256] = {};
        GetWindowText(g_hEditValue, buffer, 256);

        int modeSel = (int)SendMessageW(
            GetDlgItem(hWnd, IDC_COMBO_SEARCHMODE),
            CB_GETCURSEL, 0, 0);

        static const wchar_t* modeNames[] = {
            L"Exact Value", L"Bigger Than", L"Smaller Than",
            L"Value Between", L"Unknown Initial Value", L"Increased Value",
            L"Decreased Value",   L"Unchanged Value"
        };
        const wchar_t* modeName = (modeSel >= 0 && modeSel < _countof(modeNames))
            ? modeNames[modeSel]
            : L"Invalid Mode";

        int selIndex = (int)SendMessageW(g_hComboValueType, CB_GETCURSEL, 0, 0);
        DataType dt = static_cast<DataType>(selIndex);

        {
            std::wstring logLine =
                L"First Scan:\r\n"
                L"  Value = \"" + std::wstring(buffer) + L"\"\r\n"
                L"  Type = " + DataTypeToString(dt) + L"\r\n"
                L"  Mode = " + modeName + L"\r\n\r\n";
            Log(logLine.c_str());
            RedrawWindow(g_hOutputLog, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
        }

        SearchMode searchMode = SEARCH_EXACT;
        switch (modeSel) {
        case 0: searchMode = SEARCH_EXACT;          break;
        case 1: searchMode = SEARCH_BIGGER;         break;
        case 2: searchMode = SEARCH_SMALLER;        break;
        case 3: searchMode = SEARCH_BETWEEN;       break;
        case 4: searchMode = SEARCH_UNKNOWN_INITIAL; break;
        default:
			// Now you should never see this error again, but just in case..
            MessageBox(g_hWndMain,
                L"Only 'Exact', 'Bigger', 'Smaller', 'Value Between' or 'Unknown Initial' are allowed for first scan.",
                L"Error", MB_OK | MB_ICONERROR);
            return 0;
        }

        if (searchMode != SEARCH_UNKNOWN_INITIAL && buffer[0] == L'\0')
        {
            MessageBox(g_hWndMain, L"A value must be entered to scan.",
                L"Error", MB_OK | MB_ICONERROR);
            break;
        }

        double searchVal = 0;
        if (searchMode != SEARCH_UNKNOWN_INITIAL)
            GetSearchValueFromEdit(searchVal);

        double singleVal = 0.0;
        if (searchMode == SEARCH_BETWEEN)
        {
            // Look for - in the buffer
            std::wstring bufW(buffer);
            size_t dash = bufW.find(L'-');
            if (dash == std::wstring::npos)
            {
                MessageBox(g_hWndMain, L"Value Between must be in the form: lower-upper (e.g. 10-25).",
                    L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            // Split into two sides, convert to double
            std::wstring lowStr = bufW.substr(0, dash);
            std::wstring highStr = bufW.substr(dash + 1);
            wchar_t* endPtr = nullptr;

            double low = wcstod(lowStr.c_str(), &endPtr);
            if (endPtr == lowStr.c_str()) {
                MessageBox(g_hWndMain, L"Could not parse the lower bound.", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            double high = wcstod(highStr.c_str(), &endPtr);
            if (endPtr == highStr.c_str()) {
                MessageBox(g_hWndMain, L"Could not parse the upper bound.", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            if (low > high) {
                std::swap(low, high);
            }

            g_searchLow = low;
            g_searchHigh = high;
        }
        else if (searchMode != SEARCH_UNKNOWN_INITIAL)
        {
            // For EXACT/BIGGER/SMALLER: parse a single value
            GetSearchValueFromEdit(singleVal);
        }

        // Finally, call PerformFirstScan
        if (searchMode != SEARCH_UNKNOWN_INITIAL && searchMode != SEARCH_BETWEEN && buffer[0] == L'\0')
        {
            // Should never get here, but just in case
            MessageBox(g_hWndMain, L"A value must be entered to scan.",
                L"Error", MB_OK | MB_ICONERROR);
            break;
        }
        PerformFirstScan(singleVal, dt, searchMode);

        // Disable First Scan and remove Unknown Initial from the dropdown
        EnableWindow(g_hBtnFirstScan, FALSE);
        EnableWindow(g_hComboValueType, FALSE);
        {
            HWND hComboSearch = GetDlgItem(g_hWndMain, IDC_COMBO_SEARCHMODE);
            int idx = (int)SendMessageW(hComboSearch, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)L"Unknown Initial Value");

            if (idx != CB_ERR)
                SendMessageW(hComboSearch, CB_DELETESTRING, (WPARAM)idx, 0);

            int vbIdx = (int)SendMessageW(
                hComboSearch,
                CB_FINDSTRINGEXACT,
                (WPARAM)-1,
                (LPARAM)L"Value Between"
            );

            const wchar_t* nextModes[] = {
                L"Increased Value", L"Decreased Value",
                L"Changed Value", L"Unchanged Value"};

            for (int i = 0; i < 4; ++i) {
                // insert each one in the original order
                SendMessageW(hComboSearch, CB_INSERTSTRING, (WPARAM)(vbIdx + 1 + i), (LPARAM)nextModes[i]);
            }
        }
    }
    break;

    case IDC_BTN_NEXTSCAN:
    {
        wchar_t buffer[256] = {};
        GetWindowText(g_hEditValue, buffer, 256);

        int modeSel = (int)SendMessageW(
            GetDlgItem(hWnd, IDC_COMBO_SEARCHMODE),
            CB_GETCURSEL, 0, 0);

        static const wchar_t* modeNames[] = {
            L"Exact Value", L"Bigger Than", L"Smaller Than",
            L"Unknown Initial Value", L"Increased Value",
            L"Decreased Value",   L"Unchanged Value"
        };
        const wchar_t* modeName = (modeSel >= 0 && modeSel < _countof(modeNames))
            ? modeNames[modeSel]
            : L"Invalid Mode";

        SearchMode searchMode;
        switch (modeSel)
        {
        case 0: searchMode = SEARCH_EXACT;     break;
        case 1: searchMode = SEARCH_BIGGER;    break;
        case 2: searchMode = SEARCH_SMALLER;   break;
        case 3: searchMode = SEARCH_BETWEEN;   break;
        case 4: searchMode = SEARCH_INCREASED; break;
        case 5: searchMode = SEARCH_DECREASED; break;
        case 6: searchMode = SEARCH_CHANGED;     break;
        case 7: searchMode = SEARCH_UNCHANGED; break;
        default:
            MessageBox(g_hWndMain, L"Invalid search mode.", L"Error", MB_OK | MB_ICONERROR);
            return 0;
        }

        int selIndex = (int)SendMessageW(g_hComboValueType, CB_GETCURSEL, 0, 0);
        DataType dt = static_cast<DataType>(selIndex);

        {
            static const wchar_t* modeNames[] = {
                L"Exact Value", L"Bigger Than", L"Smaller Than",
                L"Value Between", L"Increased Value", L"Decreased Value",
                L"Unchanged Value", L"Unknown Initial Value" // 7 (should never be chosen here, but..)
            };
            const wchar_t* modeName = (modeSel >= 0 && modeSel < _countof(modeNames))
                ? modeNames[modeSel]
                : L"Invalid Mode";

            std::wstring logLine =
                L"Next Scan:\r\n"
                L"  Value = \"" + std::wstring(buffer) + L"\"\r\n"
                L"  Type = " + DataTypeToString(dt) + L"\r\n"
                L"  Mode = " + modeName + L"\r\n\r\n";
            Log(logLine.c_str());
            RedrawWindow(g_hOutputLog, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
        }

        if ((searchMode == SEARCH_INCREASED ||
            searchMode == SEARCH_DECREASED ||
            searchMode == SEARCH_UNCHANGED) &&
            (!g_scanPager || g_scanPager->Count() == 0))
        {
            MessageBox(g_hWndMain,
                L"You must perform a first scan before this mode.",
                L"Error", MB_OK | MB_ICONERROR);
            break;
        }

        double singleVal = 0.0;
        if (searchMode == SEARCH_EXACT ||
            searchMode == SEARCH_BIGGER ||
            searchMode == SEARCH_SMALLER)
        {
            if (buffer[0] == L'\0')
            {
                MessageBox(g_hWndMain, L"A value must be entered to scan.",
                    L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            GetSearchValueFromEdit(singleVal);
        }
        else if (searchMode == SEARCH_BETWEEN)
        {
            if (buffer[0] == L'\0')
            {
                MessageBox(g_hWndMain, L"A range (low-high) must be entered to scan.",
                    L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            // Parse low-upper
            std::wstring bufW(buffer);
            size_t dash = bufW.find(L'-');
            if (dash == std::wstring::npos)
            {
                MessageBox(g_hWndMain, L"Value Between must be in the form: lower-upper (e.g. 10-25).",
                    L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            std::wstring lowStr = bufW.substr(0, dash);
            std::wstring highStr = bufW.substr(dash + 1);
            wchar_t* endPtr = nullptr;

            double low = wcstod(lowStr.c_str(), &endPtr);
            if (endPtr == lowStr.c_str())
            {
                MessageBox(g_hWndMain, L"Could not parse the lower bound.", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            double high = wcstod(highStr.c_str(), &endPtr);
            if (endPtr == highStr.c_str())
            {
                MessageBox(g_hWndMain, L"Could not parse the upper bound.", L"Error", MB_OK | MB_ICONERROR);
                break;
            }
            if (low > high) std::swap(low, high);
            g_searchLow = low;
            g_searchHigh = high;
        }

        MSG tempMsg;
        g_previousScanEntries.clear();
        if (g_scanPager)
        {
            for (size_t i = 0, tot = g_scanPager->Count(); i < tot; ++i)
            {
                ScanEntry e;
                if (g_scanPager->GetEntry(i, e))
                    g_previousScanEntries.push_back(e);

                if ((i % 1000) == 0)
                {
                    while (PeekMessage(&tempMsg, NULL, 0, 0, PM_REMOVE))
                    {
                        TranslateMessage(&tempMsg);
                        DispatchMessage(&tempMsg);
                    }
                }
            }
        }

        PerformNextScan(singleVal, dt, searchMode);
    }
    break;

    case IDC_BTN_UNDOSCAN:
        if (UndoScan()) UpdateScanResultsListView();
        break;

    case IDC_BTN_NEWSCAN:
        ResetScans();

        if (g_pinnedLogLength > 0)
        {
            // preserve only the first g_pinnedLogLength chars
            int total = GetWindowTextLengthW(g_hOutputLog);
            std::wstring all(total, L'\0');
            GetWindowTextW(g_hOutputLog, &all[0], total + 1);

            std::wstring keep = all.substr(0, g_pinnedLogLength);
            SetWindowTextW(g_hOutputLog, keep.c_str());

            // scroll to the end of the pinned section
            SendMessageW(g_hOutputLog, WM_VSCROLL, SB_BOTTOM, 0);
        }
        else
        {
            int totalLen = GetWindowTextLengthW(g_hOutputLog);
            std::vector<wchar_t> buf(totalLen + 1);
            GetWindowTextW(g_hOutputLog, buf.data(), totalLen + 1);
            std::wstring logText(buf.data());

            if (g_unrealDetected) {
                size_t pos = logText.find(L"First Scan:");
                if (pos != std::wstring::npos) {
                    SendMessageW(g_hOutputLog, EM_SETSEL, pos, totalLen);
                    SendMessageW(g_hOutputLog, EM_REPLACESEL, FALSE, (LPARAM)L"");
                }
            }
            else {
                size_t attachPos = logText.rfind(L"Attached to");
                if (attachPos != std::wstring::npos) {
                    size_t cut = logText.find(L"\r\n\r\n", attachPos);
                    if (cut != std::wstring::npos) {
                        std::wstring keep = logText.substr(0, cut + 4);
                        SetWindowTextW(g_hOutputLog, keep.c_str());
                    }
                    else {
                        SetWindowTextW(g_hOutputLog, logText.c_str());
                    }
                }
                else {
                    SetWindowTextW(g_hOutputLog, L"MemRE Logs:\r\n\r\n");
                }
            }
        }

        SetWindowTextW(g_hStaticScanStatus, L"Displaying 0 values out of 0");
        SendMessageW(g_hProgressBar, PBM_SETPOS, 0, 0);
        SendMessageW(g_hOutputLog, WM_VSCROLL, SB_LINEUP, 0);
        SendMessageW(g_hOutputLog, WM_VSCROLL, SB_LINEUP, 0);
        UpdateScanButtons(false);
        EnableWindow(g_hBtnFirstScan, TRUE);
        EnableWindow(g_hComboValueType, TRUE);
        SendMessageW(g_hComboValueType, CB_SETCURSEL, 2, 0);
        {
            HWND hComboSearch = GetDlgItem(g_hWndMain, IDC_COMBO_SEARCHMODE);
            SendMessageW(hComboSearch, CB_SETCURSEL, 0, 0);
            int count = (int)SendMessageW(hComboSearch, CB_GETCOUNT, 0, 0);
            SendMessageW(hComboSearch,
                CB_INSERTSTRING,
                (WPARAM)count,
                (LPARAM)L"Unknown Initial Value");

            const wchar_t* nextModes[] = {
                L"Increased Value", L"Decreased Value",
                L"Changed Value", L"Unchanged Value"};

            for (auto* m : nextModes) {
                int idx = (int)SendMessageW(
                    hComboSearch,
                    CB_FINDSTRINGEXACT,
                    (WPARAM)-1,
                    (LPARAM)m
                );
                if (idx != CB_ERR)
                    SendMessageW(hComboSearch, CB_DELETESTRING, (WPARAM)idx, 0);
            }
        }
        break;

    case IDC_BTN_EXIT:
    {
        ResetScans();
        CleanupDatFiles(g_scanResultsFolder);
        WCHAR procName[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, procName, &size))
        {
            WCHAR* baseName = wcsrchr(procName, L'\\');
            baseName = baseName ? baseName + 1 : procName;
            if (_wcsicmp(baseName, L"MemRE.exe") == 0)
                TerminateProcess(GetCurrentProcess(), 0);
        }
        DestroyWindow(hWnd);
    }
    break;
    case IDC_BTN_SAVETABLE:
    {
        OPENFILENAMEW ofn{ sizeof(ofn) };
        wchar_t szFile[MAX_PATH] = { 0 };
        std::wstring defaultPath = g_tablesFolder + L"\\";
        if (g_isAttached && g_hTargetProcess) {
            wchar_t fullPath[MAX_PATH] = { 0 };
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &sz)) {
                wchar_t* base = wcsrchr(fullPath, L'\\');
                base = base ? base + 1 : fullPath;
                if (wcsstr(base, L".exe")) *wcsstr(base, L".exe") = L'\0';
                defaultPath += base;
            }
            else defaultPath += L"table";
        }
        else defaultPath += L"table";
        defaultPath += L".mre";
        wcscpy_s(szFile, defaultPath.c_str());
        ofn.hwndOwner = hWnd;
        ofn.lpstrFilter = L"MemRE Tables (*.mre)\0*.mre\0All Files\0*.*\0\0";
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = L"mre";
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

        if (GetSaveFileNameW(&ofn)) {
            std::wofstream out(ofn.lpstrFile);
            if (!out) {
                MessageBoxW(hWnd, L"Cannot open for writing.", L"Error", MB_OK | MB_ICONERROR);
            }
            else {
                for (auto& s : g_savedEntries) {
                    std::wstring safeDesc = s.desc;
                    for (auto& c : safeDesc)
                        if (c == L',') c = L' ';

                    wchar_t addrBuf[32];
                    swprintf(addrBuf, 32, L"%llX", (unsigned long long)s.entry.address);

                    std::wstring typeTok = std::to_wstring((int)s.savedType);

                    std::wstring valTok;
                    switch (s.savedType) {
                    case DATA_BYTE:   valTok = std::to_wstring(s.entry.value.valByte);   break;
                    case DATA_2BYTE:  valTok = std::to_wstring(s.entry.value.val2Byte);  break;
                    case DATA_4BYTE:  valTok = std::to_wstring(s.entry.value.val4Byte);  break;
                    case DATA_8BYTE:  valTok = std::to_wstring(s.entry.value.val8Byte);  break;
                    case DATA_FLOAT:  valTok = std::to_wstring(s.entry.value.valFloat);  break;
                    case DATA_DOUBLE: valTok = std::to_wstring(s.entry.value.valDouble); break;
                    default:          valTok = L"0";                                      break;
                    }

                    std::wstring ptrTok = s.pointerExpr;

                    out
                        << addrBuf << L","
                        << typeTok << L","
                        << L"" << L","
                        << L"0" << L","
                        << safeDesc << L","
                        << ptrTok << L"\n";
                }
                out.close();
            }
        }
    }
    break;
    case IDC_BTN_LOADTABLE:
    {
        OPENFILENAMEW ofn{ sizeof(ofn) };
        wchar_t szFile[MAX_PATH] = { 0 };
        wcscpy_s(szFile, (g_tablesFolder + L"\\*.mre").c_str());

        ofn.hwndOwner = hWnd;
        ofn.lpstrFilter = L"MemRE Tables (*.mre)\0*.mre\0All Files\0*.*\0\0";
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = L"mre";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameW(&ofn)) {
            LoadTableFromFile(ofn.lpstrFile);
        }
    }
    break;
    case IDC_BTN_ADDADDRESS:
        ShowAddAddressDialog(hWnd);
        break;
    case IDC_BTN_SAVECT:
    {
        CreateDirectoryW(g_tablesFolder.c_str(), nullptr);

        OPENFILENAMEW ofn{ sizeof(ofn) };
        wchar_t szFile[MAX_PATH] = { 0 };
        std::wstring defaultName = g_tablesFolder + L"\\";
        if (g_isAttached && g_hTargetProcess) {
            wchar_t fullPath[MAX_PATH] = { 0 };
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &sz)) {
                wchar_t* base = wcsrchr(fullPath, L'\\');
                base = base ? base + 1 : fullPath;
                wchar_t* dot = wcsstr(base, L".exe");
                if (dot) *dot = L'\0';
                defaultName += base;
            }
            else {
                defaultName += L"table";
            }
        }
        else {
            defaultName += L"table";
        }
        defaultName += L".CT";
        wcscpy_s(szFile, defaultName.c_str());

        ofn.hwndOwner = hWnd;
        ofn.lpstrFilter = L"Cheat Engine Tables (*.ct)\0*.ct\0All Files\0*.*\0\0";
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrDefExt = L"ct";
        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

        if (GetSaveFileNameW(&ofn)) {
            std::wofstream out(ofn.lpstrFile);
            if (!out) {
                MessageBoxW(hWnd, L"Cannot open file for writing.", L"Error", MB_OK | MB_ICONERROR);
            }
            else {
                out << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
                out << L"<CheatTable CheatEngineTableVersion=\"45\">\n";
                out << L"  <CheatEntries>\n";

                for (size_t i = 0; i < g_savedEntries.size(); ++i) {
                    const auto& s = g_savedEntries[i];
                    out << L"    <CheatEntry>\n";
                    out << L"      <ID>" << i << L"</ID>\n";

                    std::wstring desc = s.desc.empty() ? L"N/A" : s.desc;
                    for (auto& c : desc) if (c == L'"') c = L'\'';
                    out << L"      <Description>\"" << desc << L"\"</Description>\n";

                    out << L"      <ShowAsSigned>0</ShowAsSigned>\n";
                    out << L"      <VariableType>" << DataTypeToString(s.savedType) << L"</VariableType>\n";

                    if (!s.pointerExpr.empty()) {
                        std::vector<std::wstring> parts;
                        {
                            std::wistringstream ss(s.pointerExpr);
                            std::wstring tok;
                            while (std::getline(ss, tok, L',')) {
                                parts.push_back(trim(tok));
                            }
                        }
                        out << L"      <Address>" << parts[0] << L"</Address>\n";

                        if (parts.size() > 1) {
                            out << L"      <Offsets>\n";
                            for (int idx = (int)parts.size() - 1; idx >= 1; --idx) {
                                out << L"        <Offset>" << parts[idx] << L"</Offset>\n";
                            }
                            out << L"      </Offsets>\n";
                        }
                    }
                    else {
                        wchar_t addrBuf[32];
                        swprintf(addrBuf, 32, L"%llX", (unsigned long long)s.entry.address);
                        out << L"      <Address>" << addrBuf << L"</Address>\n";
                    }

                    out << L"    </CheatEntry>\n";
                }

                out << L"  </CheatEntries>\n";
                out << L"  <UserdefinedSymbols/>\n";
                out << L"</CheatTable>\n";
                out.close();
            }
        }
    }
    break;

    case IDC_BTN_OFFSET_ADD:
    {
        wchar_t buf[64] = {};
        GetWindowTextW(g_hEditOffsetEntry, buf, _countof(buf));
        if (buf[0]) {
            SendMessageW(g_hListOffsets, LB_ADDSTRING, 0, (LPARAM)buf);
            SetWindowTextW(g_hEditOffsetEntry, L"");
            int cnt = (int)SendMessageW(g_hListOffsets, LB_GETCOUNT, 0, 0);
            SendMessageW(g_hListOffsets, LB_SETTOPINDEX, cnt - 1, 0);
        }
        break;
    }

    case IDC_BTN_OFFSET_DEL:
    {
        int sel = (int)SendMessageW(g_hListOffsets, LB_GETCURSEL, 0, 0);
        if (sel != LB_ERR)
            SendMessageW(g_hListOffsets, LB_DELETESTRING, sel, 0);
        break;
    }

    case IDC_BTN_OFFSET_AUTO:
    {
        ShowAutoOffsetsDialog(hWnd, g_resolvedBaseAddress);
        break;
    }
    case IDC_BTN_POINTERSCAN:
    {
        if (!g_isPointerScanning)
        {
            {
                LONG_PTR style = GetWindowLongPtr(g_hProgressBar, GWL_STYLE);
                SetWindowLongPtr(
                    g_hProgressBar,
                    GWL_STYLE,
                    style | PBS_MARQUEE
                );
            }
            // Send PBM_SETMARQUEE to turn on the animated marquee
            SendMessage(g_hProgressBar, PBM_SETMARQUEE, TRUE, 30);
            UpdateWindow(g_hProgressBar);

            // if Scan From File is checked
            if (IsDlgButtonChecked(hWnd, IDC_CHECK_SCAN_SAVED_FILE) == BST_CHECKED)
            {
                // enter scanning state
                g_isPointerScanning = true;
                SetWindowTextW(g_hBtnPointerScan, L"Stop");

                // disable UI controls during scan from file
                EnableWindow(g_hEditBaseAddress, FALSE);
                EnableWindow(g_hDynamicAddressEdit, FALSE);
                EnableWindow(g_hEditMaxDepth, FALSE);
                EnableWindow(g_hListOffsets, FALSE);
                EnableWindow(g_hBtnAddOffset, FALSE);
                EnableWindow(g_hBtnRemoveOffset, FALSE);
                EnableWindow(g_hBtnAutoOffset, FALSE);
                EnableWindow(g_hBtnViewPTRs, FALSE);
                EnableWindow(GetDlgItem(hWnd, IDC_CHECK_SCAN_SAVED_FILE), FALSE);

                // perform filtering of loaded chains
                std::vector<std::vector<std::wstring>> active;
                for (auto& chain : g_loadedChains)
                {
                    // pass both process handle and PID to match signature
                    uintptr_t addr = ResolvePointerChain(
                        g_hTargetProcess,
                        g_targetProcessId,
                        chain
                    );
                    if (addr != 0)
                        active.push_back(chain);
                }

                // prompt user to save survivors
                int total = (int)g_loadedChains.size();
                int kept = (int)active.size();
                std::wstring msg =
                    L"Of " + std::to_wstring(total) +
                    L" saved chains, " + std::to_wstring(kept) +
                    L" are still active.\n\nSave active chains?";
                if (MessageBoxW(hWnd, msg.c_str(), L"Scan From File",
                    MB_YESNO | MB_ICONQUESTION) == IDYES)
                {
                    // default output path = original + _active.MPTR
                    std::wstring base = g_mptrFilePath.substr(
                        0, g_mptrFilePath.find_last_of(L'.')
                    ) + L"_active.MPTR";

                    wchar_t outFile[MAX_PATH];
                    wcscpy_s(outFile, base.c_str());
                    OPENFILENAMEW sfn{ sizeof(sfn) };
                    sfn.hwndOwner = hWnd;
                    sfn.lpstrFilter = L"Pointer files (*.MPTR)\0*.MPTR\0\0";
                    sfn.lpstrFile = outFile;
                    sfn.nMaxFile = MAX_PATH;
                    sfn.lpstrDefExt = L"MPTR";
                    sfn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
                    if (GetSaveFileNameW(&sfn))
                    {
                        std::wofstream fout(sfn.lpstrFile, std::ios::trunc);
                        for (auto& chain : active)
                        {
                            fout << chain[0];
                            for (size_t i = 1; i < chain.size(); ++i)
                                fout << L"," << chain[i];
                            fout << L"\n";
                        }
                    }
                }

                // restore UI and state
                g_loadedChains.clear();
                g_mptrFilePath.clear();
                g_isPointerScanning = false;
                SetWindowTextW(g_hBtnPointerScan, L"Scan");
                CheckDlgButton(hWnd, IDC_CHECK_SCAN_SAVED_FILE, BST_UNCHECKED);
                EnableWindow(g_hEditBaseAddress, TRUE);
                EnableWindow(g_hDynamicAddressEdit, TRUE);
                EnableWindow(g_hEditMaxDepth, TRUE);
                EnableWindow(g_hListOffsets, TRUE);
                EnableWindow(g_hBtnAddOffset, TRUE);
                EnableWindow(g_hBtnRemoveOffset, TRUE);
                EnableWindow(g_hBtnAutoOffset, TRUE);
                EnableWindow(g_hBtnViewPTRs, TRUE);
                EnableWindow(GetDlgItem(hWnd, IDC_CHECK_SCAN_SAVED_FILE), TRUE);

                SendMessage(g_hProgressBar, PBM_SETMARQUEE, FALSE, 0);
                {
                    LONG_PTR style = GetWindowLongPtr(g_hProgressBar, GWL_STYLE);
                    SetWindowLongPtr(
                        g_hProgressBar,
                        GWL_STYLE,
                        style & ~PBS_MARQUEE
                    );
                }
                UpdateWindow(g_hProgressBar);
            }
            else
            {
                g_stopPointerScan = false;
                g_isPointerScanning = true;
                SetWindowTextW(g_hBtnPointerScan, L"Stop");

                EnableWindow(g_hEditBaseAddress, FALSE);
                EnableWindow(g_hDynamicAddressEdit, FALSE);
                EnableWindow(g_hEditMaxDepth, FALSE);
                EnableWindow(g_hListOffsets, FALSE);
                EnableWindow(g_hBtnAddOffset, FALSE);
                EnableWindow(g_hBtnRemoveOffset, FALSE);
                EnableWindow(g_hBtnAutoOffset, FALSE);
                EnableWindow(g_hBtnViewPTRs, FALSE);
                EnableWindow(GetDlgItem(hWnd, IDC_CHECK_SCAN_SAVED_FILE), FALSE);

                wchar_t baseBuf[64] = { 0 };
                GetWindowTextW(g_hEditBaseAddress, baseBuf, _countof(baseBuf));
                std::wstring baseStr(baseBuf);
                uintptr_t baseAddr = ParsePointerAddress(baseStr);
                if (!baseAddr)
                {
                    Log(L"Error: could not parse base address\r\n\r\n");

                    // abort and restore UI
                    g_isPointerScanning = false;
                    SetWindowTextW(g_hBtnPointerScan, L"Scan");
                    EnableWindow(g_hEditBaseAddress, TRUE);
                    EnableWindow(g_hDynamicAddressEdit, TRUE);
                    EnableWindow(g_hEditMaxDepth, TRUE);
                    EnableWindow(g_hListOffsets, TRUE);
                    EnableWindow(g_hBtnAddOffset, TRUE);
                    EnableWindow(g_hBtnRemoveOffset, TRUE);
                    EnableWindow(g_hBtnAutoOffset, TRUE);
                    EnableWindow(g_hBtnViewPTRs, TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_CHECK_SCAN_SAVED_FILE), TRUE);
                    break;
                }

                wchar_t dynBuf[64] = { 0 };
                GetWindowTextW(g_hDynamicAddressEdit, dynBuf, _countof(dynBuf));
                std::wstring dynStr(dynBuf);
                uintptr_t dynAddr = ParsePointerAddress(dynStr);
                if (!dynAddr)
                {
                    Log(L"Error: could not parse dynamic address\r\n");
                    break;
                }

                // read the max‑depth out of its edit box
                wchar_t depthBuf[16] = { 0 };
                GetWindowTextW(g_hEditMaxDepth, depthBuf, _countof(depthBuf));
                int maxDepth = _wtoi(depthBuf);

                g_positionalOffsets.clear();
                int count = (int)SendMessageW(g_hListOffsets, LB_GETCOUNT, 0, 0);
                for (int i = 0; i < count; ++i)
                {
                    wchar_t buf[32] = {};
                    SendMessageW(g_hListOffsets, LB_GETTEXT, i, (LPARAM)buf);
                    DWORD_PTR off = static_cast<DWORD_PTR>(_wcstoui64(buf, nullptr, 16));
                    g_positionalOffsets.push_back(off);
                }

                // Pointer‑scan thread
                auto* sp = new PointerScanParams{
                    baseAddr,
                    dynAddr,
                    maxDepth
                };
                g_hPointerScanThread = CreateThread(
                    nullptr, 0,
                    PointerScanThreadProc,
                    sp, 0, nullptr
                );
            }
        }
        else
        {
            // user clicked Stop
            g_stopPointerScan = true;

            SendMessage(g_hProgressBar, PBM_SETMARQUEE, FALSE, 0);
            {
                LONG_PTR style = GetWindowLongPtr(g_hProgressBar, GWL_STYLE);
                SetWindowLongPtr(
                    g_hProgressBar,
                    GWL_STYLE,
                    style & ~PBS_MARQUEE
                );
            }
            UpdateWindow(g_hProgressBar);
        }
        break;
    }
    case IDC_CHECK_SCAN_SAVED_FILE:
        if (HIWORD(wParam) == BN_CLICKED &&
            IsDlgButtonChecked(hWnd, IDC_CHECK_SCAN_SAVED_FILE) == BST_CHECKED)
        {
            // Prompt user to select an existing .MPTR file
            wchar_t inFile[MAX_PATH] = {};
            OPENFILENAMEW ofn{ sizeof(ofn) };
            ofn.hwndOwner = hWnd;
            ofn.lpstrFilter = L"Pointer files (*.MPTR)\0*.MPTR\0All Files\0*.*\0\0";
            ofn.lpstrFile = inFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (!GetOpenFileNameW(&ofn)) {
                // User cancelled: reset checkbox and exit
                CheckDlgButton(hWnd, IDC_CHECK_SCAN_SAVED_FILE, BST_UNCHECKED);
                break;
            }

            // Remember path and load pointer chains into memory
            g_mptrFilePath = inFile;
            g_loadedChains.clear();
            std::wifstream fin(inFile);
            std::wstring line;
            while (std::getline(fin, line)) {
                if (line.empty())
                    continue;
                g_loadedChains.push_back(splitPointerExpr(line));
            }

        }
        break;

    case IDC_BTN_VIEWPTRS:
    {
        // Prompt for an existing .MPTR file
        wchar_t szFile[MAX_PATH] = {};
        OPENFILENAMEW ofn{ sizeof(ofn) };
        ofn.hwndOwner = g_hWndMain;
        ofn.lpstrFilter = L"Pointer files (*.MPTR)\0*.MPTR\0All Files\0*.*\0\0";
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        if (!GetOpenFileNameW(&ofn))
            break;

        // Load each comma‑delimited chain into g_loadedChains
        g_mptrFilePath = szFile;
        g_loadedChains.clear();
        std::wifstream fin(szFile);
        std::wstring  line;
        while (std::getline(fin, line))
            if (!line.empty())
                g_loadedChains.push_back(splitPointerExpr(line));

        // Show the pointer‑table dialog
        ShowPointerTableDialog(g_hWndMain);
    }
    break;

    case ID_MENU_ATTACH:
    {
        HMENU hMenu = GetMenu(hWnd);
        MENUITEMINFO mii = { sizeof(mii) };
        mii.fMask = MIIM_STRING;

        if (!g_isAttached)
        {
            g_targetPID = 0;
            SelectProcessDialog(hWnd);
            if (g_targetPID)
                AttachToProcess(g_targetPID);
        }
        else
        {
            DWORD oldPID = g_targetProcessId;
            WCHAR procPath[MAX_PATH] = {};
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(g_hTargetProcess, 0, procPath, &sz))
            {
                WCHAR* exeName = wcsrchr(procPath, L'\\');
                exeName = exeName ? exeName + 1 : procPath;
                std::wstring line =
                    L"Detached from " +
                    std::wstring(exeName) +
                    L" (PID: " +
                    std::to_wstring(oldPID) +
                    L")\r\n\r\n";
                Log(line.c_str());
            }

            if (g_hTargetProcess && g_hTargetProcess != GetCurrentProcess())
                CloseHandle(g_hTargetProcess);

            g_hTargetProcess = g_hOriginalProcess;
            g_targetProcessId = g_originalProcessId;
            g_isAttached = false;

            HMENU hMenu = GetMenu(hWnd);
            MENUITEMINFO mii = { sizeof(mii) };
            mii.fMask = MIIM_STRING;
            mii.dwTypeData = const_cast<LPWSTR>(L"Attach");
            SetMenuItemInfoW(hMenu, ID_MENU_ATTACH, FALSE, &mii);

            WCHAR myPath[MAX_PATH];
            DWORD mySz = GetModuleFileNameW(NULL, myPath, MAX_PATH);
            WCHAR* myExe = wcsrchr(myPath, L'\\');
            myExe = myExe ? myExe + 1 : myPath;
            WCHAR info[128];
            swprintf_s(info, _countof(info), L"%s (PID: %lu)", myExe, g_originalProcessId);
            MENUITEMINFO miiInfo = { sizeof(miiInfo) };
            miiInfo.fMask = MIIM_STRING;
            miiInfo.dwTypeData = info;
            SetMenuItemInfoW(hMenu, ID_MENU_PROCINFO, FALSE, &miiInfo);

            DrawMenuBar(hWnd);
            EnableWindow(g_hBtnAutoOffset, FALSE);
        }
        break;
    }
    case ID_MENU_THREAD:
    {
        g_targetPID = 0;

        wchar_t origBaseText[64] = {};
        GetWindowTextW(g_hEditBaseAddress, origBaseText, _countof(origBaseText));
        uintptr_t origResolved = g_resolvedBaseAddress;

        SelectProcessDialog(hWnd);
        if (!g_targetPID)
            break;

        // Inject
        InjectSelfIntoProcess(g_targetPID);

        // Open the log with injection info:
        {
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                g_targetPID
            );
            if (hProc)
            {
                // figure out the exe name
                wchar_t fullPath[MAX_PATH]{};
                DWORD len = MAX_PATH;
                QueryFullProcessImageNameW(hProc, 0, fullPath, &len);
                wchar_t* exePtr = wcsrchr(fullPath, L'\\');
                const wchar_t* exeName = exePtr ? exePtr + 1 : fullPath;

                // grab module base
                HMODULE hMods[1];
                DWORD cbNeeded = 0;
                if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
                {
                    MODULEINFO mi{};
                    if (GetModuleInformation(hProc, hMods[0], &mi, sizeof(mi)))
                    {
                        wchar_t buf[64];
                        swprintf(buf, 64,
                            L"Base Address: 0x%llX\r\n\r\n",
                            (unsigned long long)mi.lpBaseOfDll);
                        // Log(buf);

                         // also update the base‑address edit
                        wchar_t editBuf[32];
                        swprintf(editBuf, 32,
                            L"%llX",
                            (unsigned long long)mi.lpBaseOfDll);
                        SetWindowTextW(g_hEditBaseAddress, editBuf);
                        g_resolvedBaseAddress = (uintptr_t)mi.lpBaseOfDll;
                    }
                }
                CloseHandle(hProc);
            }
        }

        SetWindowTextW(g_hEditBaseAddress, origBaseText);
        g_resolvedBaseAddress = origResolved;

        // make sure the log actually redraws immediately
        RedrawWindow(g_hOutputLog, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW);
    }
    break;
    case ID_MENU_SETTINGS:
    {
        HMENU hPopup = CreatePopupMenu();
        AppendMenuW(hPopup, MF_STRING, ID_MENU_HOTKEYS, L"Hotkeys");
        AppendMenuW(hPopup, MF_STRING, ID_MENU_SUPPORT, L"Support");

        POINT pt;
        GetCursorPos(&pt);
        TrackPopupMenu(hPopup,
            TPM_LEFTALIGN | TPM_TOPALIGN,
            pt.x, pt.y,
            0, hWnd, NULL);
        DestroyMenu(hPopup);
    }
    break;

    case ID_MENU_HOTKEYS:
        // TODO: open your Hotkeys dialog
        MessageBoxW(hWnd, L"Hotkeys settings coming soon…", L"Settings – Hotkeys", MB_OK);
        break;

    case ID_MENU_SUPPORT:
    {
        // Configure the Task Dialog
        TASKDIALOGCONFIG tdc = {};
        tdc.cbSize = sizeof(tdc);
        tdc.hwndParent = hWnd;
        tdc.dwFlags = TDF_ENABLE_HYPERLINKS;
        tdc.pszWindowTitle = L"Settings – Support";
        tdc.pszMainInstruction = L"Need Support?";
        tdc.pszContent =
            L"Visit <a href=\"https://memre.io\">memre.io</a> or join MemRE "
            L"<a href=\"https://discord.gg/7nGkqwdJhn\">Discord</a>.";

        // Callback to catch hyperlink clicks
        tdc.pfCallback = [](HWND, UINT notification, WPARAM wp, LPARAM lp, LONG_PTR) -> HRESULT {
            if (notification == TDN_HYPERLINK_CLICKED) {
                LPCWSTR uri = reinterpret_cast<LPCWSTR>(lp);
                ShellExecuteW(NULL, L"open", uri, NULL, NULL, SW_SHOWNORMAL);
            }
            return S_OK;
        };

        TaskDialogIndirect(&tdc, nullptr, nullptr, nullptr);
    }
    break;
    default:
        return DefWindowProcW(hWnd, WM_COMMAND, wParam, lParam);
    }
    return 0;
}

static LRESULT Handle_Destroy(HWND hWnd)
{
    KillTimer(hWnd, IDT_UPDATE_TIMER);
    PostQuitMessage(0);
    return 0;
}

// — Other Helpers
bool IsReadable(DWORD protect)
{
    if (protect & PAGE_GUARD)
        return false;
    return (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) ||
        (protect & PAGE_WRITECOPY) || (protect & PAGE_EXECUTE_READ) ||
        (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_EXECUTE_WRITECOPY);
}

bool GetSearchValueFromEdit(double& value)
{
    wchar_t buffer[256] = { 0 };
    GetWindowText(g_hEditValue, buffer, 256);
    value = wcstod(buffer, nullptr);
    return true;
}


// ————————————————————————————————————————————————————————————————
// Dialog Procedures: Add / Edit Address
// ————————————————————————————————————————————————————————————————
LRESULT CALLBACK AddAddressDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:

        CreateWindowW(
            L"STATIC", L"Address:",
            WS_CHILD | WS_VISIBLE,
            10, 10, 260, 20,
            hDlg, NULL,
            (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE),
            NULL
        );

        CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            10, 35, 260, 25,
            hDlg, (HMENU)IDC_ADD_EDITADDRESS,
            (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE),
            NULL
        );

        {
            HWND hCombo = CreateWindowExW(
                WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                10, 70, 260, 100,
                hDlg, (HMENU)IDC_ADD_COMBOTYPE,
                (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE),
                NULL
            );
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"Byte");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"2 Byte");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"4 Byte");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"8 Byte");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"Float");
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"Double");
            SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
        }

        CreateWindowW(
            L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            10, 110, 120, 30,
            hDlg, (HMENU)IDC_ADD_OK,
            (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE),
            NULL
        );
        CreateWindowW(
            L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            150, 110, 120, 30,
            hDlg, (HMENU)IDC_ADD_CANCEL,
            (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE),
            NULL
        );
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_ADD_OK:
        {
            SavedEntry saved{};
            wchar_t buf[128] = { 0 };
            GetWindowTextW(GetDlgItem(hDlg, IDC_ADD_EDITADDRESS), buf, _countof(buf));
            std::wstring expr = trim(buf);
            saved.pointerExpr = expr;

            std::vector<std::wstring> parts;
            wchar_t* ctx = nullptr;
            for (wchar_t* tok = wcstok_s(buf, L",", &ctx); tok; tok = wcstok_s(nullptr, L",", &ctx))
                parts.emplace_back(tok);
            if (parts.empty()) break;

            uintptr_t finalAddr = ResolvePointerChain(g_hTargetProcess, g_targetProcessId, parts);
            if (!finalAddr) break;

            int sel = (int)SendMessageW(GetDlgItem(hDlg, IDC_ADD_COMBOTYPE), CB_GETCURSEL, 0, 0);
            DataType dt = DATA_BYTE;
            switch (sel) {
            case 0: dt = DATA_BYTE;   break;
            case 1: dt = DATA_2BYTE;  break;
            case 2: dt = DATA_4BYTE;  break;
            case 3: dt = DATA_8BYTE;  break;
            case 4: dt = DATA_FLOAT;  break;
            case 5: dt = DATA_DOUBLE; break;
            }

            saved.freeze = false;
            saved.entry.address = finalAddr;
            saved.entry.dataType = dt;
            saved.savedType = dt;
            switch (dt) {
            case DATA_BYTE: {
                uint8_t v = 0;
                ReadProcessMemory(g_hTargetProcess, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                saved.entry.value.valByte = v;
            } break;
            case DATA_2BYTE: {
                uint16_t v = 0;
                ReadProcessMemory(g_hTargetProcess, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                saved.entry.value.val2Byte = v;
            } break;
            case DATA_4BYTE: {
                uint32_t v = 0;
                ReadProcessMemory(g_hTargetProcess, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                saved.entry.value.val4Byte = v;
            } break;
            case DATA_8BYTE: {
                uint64_t v = 0;
                ReadProcessMemory(g_hTargetProcess, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                saved.entry.value.val8Byte = v;
            } break;
            case DATA_FLOAT: {
                float v = 0.0f;
                ReadProcessMemory(g_hTargetProcess, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                saved.entry.value.valFloat = v;
            } break;
            case DATA_DOUBLE: {
                double v = 0.0;
                ReadProcessMemory(g_hTargetProcess, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                saved.entry.value.valDouble = v;
            } break;
            }

            g_savedEntries.push_back(saved);
            AppendSavedAddress(saved);
            DestroyWindow(hDlg);
        }
        break;

        case IDC_ADD_CANCEL:
            DestroyWindow(hDlg);
            break;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hDlg);
        break;

    default:
        return DefWindowProcW(hDlg, message, wParam, lParam);
    }

    return 0;
}

void ShowAddAddressDialog(HWND hParent)
{
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = AddAddressDlgProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"AddAddressDlgClass";
    RegisterClassW(&wc);
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"AddAddressDlgClass", L"Add Address", WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, 190, hParent, NULL, GetModuleHandleW(NULL), NULL);
    if (!hDlg) return;
    RECT rcParent, rcDlg;
    GetWindowRect(hParent, &rcParent);
    GetWindowRect(hDlg, &rcDlg);
    int posX = rcParent.left + (((rcParent.right - rcParent.left) - (rcDlg.right - rcDlg.left)) / 2);
    int posY = rcParent.top + (((rcParent.bottom - rcParent.top) - (rcDlg.bottom - rcDlg.top)) / 2);
    SetWindowPos(hDlg, NULL, posX, posY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    MSG msg;
    while (IsWindow(hDlg))
    {
        if (GetMessage(&msg, NULL, 0, 0))
        {
            if (!IsDialogMessage(hDlg, &msg))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
}

LRESULT CALLBACK EditAddressDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        HINSTANCE hInst = GetModuleHandleW(NULL);
        const SavedEntry& S = g_savedEntries[g_editAddressIndex];

        CreateWindowW(
            L"STATIC", L"Address:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 10, 60, 20,
            hDlg, NULL, hInst, NULL
        );

        wchar_t addrBuf[64];
        swprintf_s(addrBuf, _countof(addrBuf), L"%llX",
            (unsigned long long)S.entry.address);
        HWND hAddrDisplay = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", addrBuf,
            WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL,
            75, 10, 200, 20,
            hDlg, NULL, hInst, NULL
        );
        SendMessageW(hAddrDisplay, EM_SETSEL, 0, -1);

        std::wstring initExpr = S.pointerExpr.empty()
            ? addrBuf
            : S.pointerExpr;
        HWND hAddrEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", initExpr.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            10, 40, 260, 25,
            hDlg, (HMENU)IDC_ADD_EDITADDRESS, hInst, NULL
        );

        HWND hCombo = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            10, 75, 260, 100,
            hDlg, (HMENU)IDC_ADD_COMBOTYPE, hInst, NULL
        );
        for (auto* opt : { L"Byte", L"2 Byte", L"4 Byte", L"8 Byte", L"Float", L"Double" })
            SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)opt);
        SendMessageW(hCombo, CB_SETCURSEL, (WPARAM)S.savedType, 0);

        CreateWindowW(
            L"BUTTON", L"OK",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            10, 115, 120, 30,
            hDlg, (HMENU)IDC_ADD_OK, hInst, NULL
        );
        CreateWindowW(
            L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            150, 115, 120, 30,
            hDlg, (HMENU)IDC_ADD_CANCEL, hInst, NULL
        );

        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_ADD_OK:
        {
            wchar_t buf[128] = { 0 };
            GetWindowTextW(GetDlgItem(hDlg, IDC_ADD_EDITADDRESS), buf, _countof(buf));
            std::wstring expr = trim(buf);
            if (expr.empty()) break;

            std::vector<std::wstring> parts;
            wchar_t* ctx = nullptr;
            for (wchar_t* tok = wcstok_s(&buf[0], L",", &ctx);
                tok;
                tok = wcstok_s(nullptr, L",", &ctx))
            {
                parts.emplace_back(trim(tok));
            }
            if (parts.empty()) break;

            uintptr_t finalAddr = ResolvePointerChain(
                g_hTargetProcess,
                g_targetProcessId,
                parts
            );
            if (!finalAddr) break;

            int sel = (int)SendMessageW(
                GetDlgItem(hDlg, IDC_ADD_COMBOTYPE),
                CB_GETCURSEL, 0, 0
            );
            DataType dt = static_cast<DataType>(sel);

            SavedEntry& target = g_savedEntries[g_editAddressIndex];
            target.pointerExpr = expr;
            target.entry.address = finalAddr;
            target.entry.dataType = dt;
            target.savedType = dt;

            HANDLE hProc = g_hTargetProcess;
            switch (dt)
            {
            case DATA_BYTE:
            {
                uint8_t v = 0;
                ReadProcessMemory(hProc, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                target.entry.value.valByte = v;
            } break;
            case DATA_2BYTE:
            {
                uint16_t v = 0;
                ReadProcessMemory(hProc, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                target.entry.value.val2Byte = v;
            } break;
            case DATA_4BYTE:
            {
                uint32_t v = 0;
                ReadProcessMemory(hProc, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                target.entry.value.val4Byte = v;
            } break;
            case DATA_8BYTE:
            {
                uint64_t v = 0;
                ReadProcessMemory(hProc, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                target.entry.value.val8Byte = v;
            } break;
            case DATA_FLOAT:
            {
                float v = 0.0f;
                ReadProcessMemory(hProc, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                target.entry.value.valFloat = v;
            } break;
            case DATA_DOUBLE:
            {
                double v = 0.0;
                ReadProcessMemory(hProc, (LPCVOID)finalAddr, &v, sizeof(v), nullptr);
                target.entry.value.valDouble = v;
            } break;
            default:
                break;
            }

            wchar_t txt[64];
            swprintf(txt, 64, L"%llX", (unsigned long long)finalAddr);
            ListView_SetItemText(
                g_hListSavedAddresses,
                g_editAddressIndex,
                2,
                txt
            );

            std::wstring typeName = DataTypeToString(dt);
            ListView_SetItemText(
                g_hListSavedAddresses,
                g_editAddressIndex,
                3,
                const_cast<LPWSTR>(typeName.c_str())
            );

            switch (dt)
            {
            case DATA_BYTE:   swprintf(txt, 64, L"%u", target.entry.value.valByte);   break;
            case DATA_2BYTE:  swprintf(txt, 64, L"%u", target.entry.value.val2Byte);  break;
            case DATA_4BYTE:  swprintf(txt, 64, L"%u", target.entry.value.val4Byte);  break;
            case DATA_8BYTE:  swprintf(txt, 64, L"%llu", target.entry.value.val8Byte); break;
            case DATA_FLOAT:  swprintf(txt, 64, L"%.4f", target.entry.value.valFloat);  break;
            case DATA_DOUBLE: swprintf(txt, 64, L"%.4f", target.entry.value.valDouble); break;
            default:          swprintf(txt, 64, L"Unknown");                         break;
            }
            ListView_SetItemText(
                g_hListSavedAddresses,
                g_editAddressIndex,
                4,
                txt
            );

            DestroyWindow(hDlg);
            return 0;
        }

        case IDC_ADD_CANCEL:
            DestroyWindow(hDlg);
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hDlg);
        return 0;
    }

    return DefWindowProcW(hDlg, message, wParam, lParam);
}

void ShowEditAddressDialog(HWND hParent, int index)
{
    g_editAddressIndex = index;
    static bool reg = false;
    if (!reg)
    {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = EditAddressDlgProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.lpszClassName = L"EditAddressDlgClass";
        RegisterClassW(&wc);
        reg = true;
    }
    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"EditAddressDlgClass",
        L"Edit Address",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 190,
        hParent, NULL, GetModuleHandleW(NULL), NULL
    );
    if (!hDlg) return;
    RECT pr, dr; GetWindowRect(hParent, &pr); GetWindowRect(hDlg, &dr);
    int x = pr.left + ((pr.right - pr.left) - (dr.right - dr.left)) / 2;
    int y = pr.top + ((pr.bottom - pr.top) - (dr.bottom - dr.top)) / 2;
    SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
}


// ————————————————————————————————————————————————————————————————
// In‑place Edit Controls
// ————————————————————————————————————————————————————————————————
LRESULT CALLBACK SubItemEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) { EndSubItemEdit(hWnd, true); return 0; }
        else if (wParam == VK_ESCAPE) { EndSubItemEdit(hWnd, false); return 0; }
        break;
    case WM_KILLFOCUS:
        if (g_editingSubItem == 2) { EndSubItemEdit(hWnd, false); }
        else if (g_editingSubItem == 4) { EndSubItemEdit(hWnd, true); }
        else { EndSubItemEdit(hWnd, false); }
        break;
    }
    return CallWindowProc(g_editOldProc, hWnd, msg, wParam, lParam);
}

static LRESULT CALLBACK EditOffsetProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        HWND hParent = GetParent(hWnd);
        SendMessageW(hParent, WM_COMMAND, MAKELONG(IDC_BTN_OFFSET_ADD, BN_CLICKED), 0);
        return 0;
    }
    return CallWindowProcW(g_oldOffsetEditProc, hWnd, msg, wParam, lParam);
}

void EndSubItemEdit(HWND hEdit, bool commit)
{
    if (!hEdit) return;
    wchar_t newText[256] = { 0 };
    GetWindowText(hEdit, newText, 256);
    DestroyWindow(hEdit);
    g_hSubItemEdit = NULL;
    if (g_editingSubItem == 2)
    {
        wchar_t origText[256] = { 0 };
        ListView_GetItemText(g_hListSavedAddresses, g_editingItem, 2, origText, 256);
        ListView_SetItemText(g_hListSavedAddresses, g_editingItem, 2, origText);
        g_editingItem = -1;
        g_editingSubItem = -1;
        return;
    }
    if (g_editingSubItem == 1)
    {
        g_savedEntries[g_editingItem].desc = newText;
        ListView_SetItemText(g_hListSavedAddresses, g_editingItem, g_editingSubItem, newText);
        g_editingItem = -1;
        g_editingSubItem = -1;
        return;
    }
    if (!commit) { g_editingItem = -1; g_editingSubItem = -1; return; }
    ListView_SetItemText(g_hListSavedAddresses, g_editingItem, g_editingSubItem, newText);
    if (g_editingItem >= 0 && g_editingItem < (int)g_savedEntries.size())
    {
        SavedEntry& saved = g_savedEntries[g_editingItem];
        HANDLE hProc = g_hTargetProcess;
        DWORD oldProtect;
        switch (saved.savedType)
        {
        case DATA_BYTE:
        {
            uint8_t newVal = (uint8_t)_wtoi(newText); saved.entry.value.valByte = newVal;
            if (VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(hProc, (LPVOID)saved.entry.address, &newVal, sizeof(newVal), NULL);
                VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), oldProtect, &oldProtect);
            }
        }
        break;
        case DATA_2BYTE:
        {
            uint16_t newVal = (uint16_t)_wtoi(newText); saved.entry.value.val2Byte = newVal;
            if (VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(hProc, (LPVOID)saved.entry.address, &newVal, sizeof(newVal), NULL);
                VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), oldProtect, &oldProtect);
            }
        }
        break;
        case DATA_4BYTE:
        {
            uint32_t newVal = (uint32_t)_wtoi(newText); saved.entry.value.val4Byte = newVal;
            if (VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(hProc, (LPVOID)saved.entry.address, &newVal, sizeof(newVal), NULL);
                VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), oldProtect, &oldProtect);
            }
        }
        break;
        case DATA_8BYTE:
        {
            uint64_t newVal = _wtoi64(newText); saved.entry.value.val8Byte = newVal;
            if (VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(hProc, (LPVOID)saved.entry.address, &newVal, sizeof(newVal), NULL);
                VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), oldProtect, &oldProtect);
            }
        }
        break;
        case DATA_FLOAT:
        {
            float newVal = (float)_wtof(newText); saved.entry.value.valFloat = newVal;
            if (VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(hProc, (LPVOID)saved.entry.address, &newVal, sizeof(newVal), NULL);
                VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), oldProtect, &oldProtect);
            }
        }
        break;
        case DATA_DOUBLE:
        {
            double newVal = _wtof(newText); saved.entry.value.valDouble = newVal;
            if (VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(hProc, (LPVOID)saved.entry.address, &newVal, sizeof(newVal), NULL);
                VirtualProtectEx(hProc, (LPVOID)saved.entry.address, sizeof(newVal), oldProtect, &oldProtect);
            }
        }
        break;
        default: break;
        }
    }
    g_editingItem = -1;
    g_editingSubItem = -1;
}

void SubclassEditControl(HWND hEdit)
{
    g_editOldProc = (WNDPROC)SetWindowLongPtr(hEdit, GWLP_WNDPROC, (LONG_PTR)SubItemEditProc);
}


// ————————————————————————————————————————————————————————————————
// List / Log Controls
// ————————————————————————————————————————————————————————————————
static LRESULT CALLBACK OffsetsListProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CONTEXTMENU) {
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, IDC_OFFSET_CLEAR, L"Clear Offsets");
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (pt.x == -1 && pt.y == -1) {
            RECT rc; GetWindowRect(hwnd, &rc);
            pt.x = rc.left + 5; pt.y = rc.top + 5;
        }
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
        return 0;
    }
    if (msg == WM_COMMAND && LOWORD(wParam) == IDC_OFFSET_CLEAR) {
        SendMessageW(g_hListOffsets, LB_RESETCONTENT, 0, 0);
        return 0;
    }
    return CallWindowProcW(g_oldOffsetsProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK LogEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
        SetFocus(g_hWndMain);
        break;

    case WM_CONTEXTMENU:
    {
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, IDC_LOG_COPY, L"Copy");
        AppendMenuW(hMenu, MF_STRING, IDC_LOG_SELECTALL, L"Select All");
        AppendMenuW(hMenu, MF_STRING, IDC_LOG_PIN, L"Pin Log");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hMenu, MF_STRING, IDC_CLEAR_LOGS, L"Clear Logs");

        POINT pt;
        if (GET_X_LPARAM(lParam) == -1 && GET_Y_LPARAM(lParam) == -1)
            GetCursorPos(&pt);
        else {
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
        }
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_LOG_COPY:
            SendMessageW(hwnd, WM_COPY, 0, 0);
            break;

        case IDC_LOG_SELECTALL:
            SendMessageW(hwnd, EM_SETSEL, 0, -1);
            break;

        case IDC_LOG_PIN:
        {
            // 1) append a marker
            Log(L"Logs Pinned\r\n\r\n");
            RedrawWindow(g_hOutputLog, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW);

            // 2) remember everything up to here
            g_pinnedLogLength = GetWindowTextLengthW(g_hOutputLog);

            return 0;
        }

        case IDC_CLEAR_LOGS:
            SetWindowTextW(g_hOutputLog, L"MemRE Logs:\r\n\r\n");
            g_pinnedLogLength = 0;
            break;
        }
        return 0;
    }

    return CallWindowProcW(g_oldLogProc, hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK BaseAddrEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CONTEXTMENU:
    {
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, IDM_COPY_MODULE_ADDR, L"Copy Module Address");
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (pt.x == -1 && pt.y == -1)
        {
            RECT rc; GetWindowRect(hWnd, &rc);
            pt.x = rc.left + 5; pt.y = rc.top + 5;
        }
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
        DestroyMenu(hMenu);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDM_COPY_MODULE_ADDR)
        {
            wchar_t addrText[32] = {};
            GetWindowTextW(hWnd, addrText, _countof(addrText));
            uintptr_t absoluteAddr = wcstoull(addrText, nullptr, 16);

            HMODULE hMods[1];
            DWORD   cbNeeded = 0;
            if (EnumProcessModules(g_hTargetProcess, hMods, sizeof(hMods), &cbNeeded))
            {

                wchar_t moduleName[MAX_PATH];
                GetModuleBaseNameW(g_hTargetProcess, hMods[0], moduleName, MAX_PATH);

                MODULEINFO mi = {};
                if (GetModuleInformation(g_hTargetProcess, hMods[0], &mi, sizeof(mi)))
                {
                    uintptr_t moduleBase = (uintptr_t)mi.lpBaseOfDll;
                    uintptr_t rva = absoluteAddr - moduleBase;

                    wchar_t copyBuf[128];
                    swprintf(copyBuf, _countof(copyBuf),
                        L"%s+%llX",
                        moduleName,
                        (unsigned long long)rva);

                    if (OpenClipboard(hWnd))
                    {
                        EmptyClipboard();
                        size_t bytes = (wcslen(copyBuf) + 1) * sizeof(wchar_t);
                        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
                        if (hMem)
                        {
                            void* pMem = GlobalLock(hMem);
                            if (pMem)
                            {
                                memcpy(pMem, copyBuf, bytes);
                                GlobalUnlock(hMem);
                                if (SetClipboardData(CF_UNICODETEXT, hMem) == NULL)
                                {
                                    GlobalFree(hMem);
                                }
                            }
                            else
                            {
                                GlobalFree(hMem);
                            }
                        }
                        CloseClipboard();
                    }
                }
            }
            return 0;
        }
        break;
    }
    return CallWindowProcW(g_oldBaseAddrProc, hWnd, msg, wParam, lParam);
}

//===========================================================================
// UI Helpers
//===========================================================================
void UpdateScanButtons(bool enabled)
{
    EnableWindow(g_hBtnNextScan, enabled);
    EnableWindow(g_hBtnUndoScan, enabled);
    EnableWindow(g_hBtnNewScan, enabled);
}

void PromptLoadSavedTableForProcess(const std::wstring& exeBaseName)
{
    std::wstring pattern = g_tablesFolder + L"\\" + exeBaseName + L"*.mre";

    WIN32_FIND_DATAW ffd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        std::wstring fileName = ffd.cFileName;
        std::wstring fullPath = g_tablesFolder + L"\\" + fileName;

        int choice = MessageBoxW(
            g_hWndMain,
            (L"Would you like to load " + fileName + L" table?").c_str(),
            L"Load Saved Table",
            MB_YESNO | MB_ICONQUESTION
        );

        if (choice == IDYES) {
            LoadTableFromFile(fullPath);
            break;
        }
    } while (FindNextFileW(hFind, &ffd));

    FindClose(hFind);
}

void ResolvePendingSavedEntries()
{
    bool oldSuppress = g_suppressLoadErrors;
    g_suppressLoadErrors = true;
    s_errorPromptShown = false;

    for (int i = 0; i < (int)g_savedEntries.size(); ++i)
    {
        auto& s = g_savedEntries[i];

        if (!s.pointerExpr.empty())
        {
            // Re‐resolve pointer chain
            std::vector<std::wstring> parts;
            std::wistringstream ss(s.pointerExpr);
            std::wstring tok;
            while (std::getline(ss, tok, L',')) {
                parts.push_back(trim(tok));
            }

            uintptr_t addr = ResolvePointerChain(
                g_hTargetProcess,
                g_targetProcessId,
                parts
            );

            // Update address column
            wchar_t addrBuf[32];
            if (addr)
                swprintf(addrBuf, 32, L"%llX", (unsigned long long)addr);
            else
                wcscpy_s(addrBuf, 32, L"Pending…");
            ListView_SetItemText(g_hListSavedAddresses, i, 2, addrBuf);

            if (addr)
            {
                s.entry.address = addr;

                // only pull in a new value if this entry is NOT frozen
                if (!s.freeze)
                {
                    wchar_t valBuf[64] = { 0 };
                    switch (s.savedType)
                    {
                    case DATA_BYTE:
                    {
                        uint8_t v = 0;
                        ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                        s.entry.value.valByte = v;
                        swprintf(valBuf, 64, L"%u", v);
                    } break;

                    case DATA_2BYTE:
                    {
                        uint16_t v = 0;
                        ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                        s.entry.value.val2Byte = v;
                        swprintf(valBuf, 64, L"%u", v);
                    } break;

                    case DATA_4BYTE:
                    {
                        uint32_t v = 0;
                        ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                        s.entry.value.val4Byte = v;
                        swprintf(valBuf, 64, L"%u", v);
                    } break;

                    case DATA_8BYTE:
                    {
                        uint64_t v = 0;
                        ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                        s.entry.value.val8Byte = v;
                        swprintf(valBuf, 64, L"%llu", (unsigned long long)v);
                    } break;

                    case DATA_FLOAT:
                    {
                        float v = 0.0f;
                        ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                        s.entry.value.valFloat = v;
                        swprintf(valBuf, 64, L"%.4f", v);
                    } break;

                    case DATA_DOUBLE:
                    {
                        double v = 0.0;
                        ReadProcessMemory(g_hTargetProcess, (LPCVOID)addr, &v, sizeof(v), nullptr);
                        s.entry.value.valDouble = v;
                        swprintf(valBuf, 64, L"%.4f", v);
                    } break;

                    default:
                        break;
                    }

                    ListView_SetItemText(g_hListSavedAddresses, i, 4, valBuf);
                }
            }
        }
    }

    g_suppressLoadErrors = oldSuppress;
}


//===========================================================================
// Scanning Engine
//===========================================================================

bool PerformFirstScan(double searchVal, DataType dt, SearchMode searchMode)
{
    g_candidateCount.store(0);
    if (g_scanPager) { delete g_scanPager; g_scanPager = nullptr; }
    for (auto p : g_undoStack) delete p;
    g_undoStack.clear();
    g_firstScanEntries.clear();
    g_previousScanEntries.clear();
    g_lastDisplayedEntries.clear();

    g_scanPager = new ScanResultPager(g_scanResultsFolder, MAPPED_PAGE_ENTRIES, ++g_currentScanId);
    HANDLE hProcess = g_hTargetProcess;

    SYSTEM_INFO si;  GetSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)si.lpMaximumApplicationAddress;
    std::vector<MemoryRegion> regions;
    MEMORY_BASIC_INFORMATION mbi;
    while (a < end)
    {
        if (VirtualQueryEx(hProcess, (LPCVOID)a, &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
        {
            regions.push_back({ a, mbi.RegionSize });
        }
        a += mbi.RegionSize;
    }

    std::atomic<size_t> bytesScanned{ 0 };
    size_t totalBytes = 0;
    for (auto& r : regions) totalBytes += r.size;

    unsigned numThreads = std::thread::hardware_concurrency();
    if (!numThreads) numThreads = 2;
    size_t perThread = regions.size() / numThreads;
    size_t rem = regions.size() % numThreads;

    std::vector<std::vector<ScanEntry>> results(numThreads);
    std::vector<std::thread> workers;

    auto worker = [&](size_t start, size_t end, size_t idx) {
        auto& out = results[idx];
        SIZE_T stride =
            dt == DATA_BYTE ? 1
            : dt == DATA_2BYTE ? 2
            : dt == DATA_4BYTE ? 4
            : dt == DATA_8BYTE ? 8
            : dt == DATA_FLOAT ? sizeof(float)
            : sizeof(double);

        for (size_t i = start; i < end; ++i)
        {
            const auto& mr = regions[i];
            std::vector<BYTE> buf(mr.size);
            SIZE_T br = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)mr.start, buf.data(), mr.size, &br))
            {
                for (SIZE_T j = 0; j + stride <= br; ++j)
                {
                    ScanEntry e{ mr.start + j, {}, dt };
                    bool match = false;
                    switch (dt)
                    {
                    case DATA_BYTE: {
                        uint8_t v = buf[j];
                        match = (searchMode == SEARCH_UNKNOWN_INITIAL)
                            || (searchMode == SEARCH_EXACT && (double)v == searchVal)
                            || (searchMode == SEARCH_BIGGER && (double)v > searchVal)
                            || (searchMode == SEARCH_SMALLER && (double)v < searchVal)
                            || (searchMode == SEARCH_BETWEEN && ((double)v >= g_searchLow && (double)v <= g_searchHigh));
                        if (match) e.value.valByte = v;
                    } break;

                    case DATA_2BYTE: {
                        uint16_t v = *reinterpret_cast<uint16_t*>(buf.data() + j);
                        match = (searchMode == SEARCH_UNKNOWN_INITIAL)
                            || (searchMode == SEARCH_EXACT && (double)v == searchVal)
                            || (searchMode == SEARCH_BIGGER && (double)v > searchVal)
                            || (searchMode == SEARCH_SMALLER && (double)v < searchVal)
                            || (searchMode == SEARCH_BETWEEN && ((double)v >= g_searchLow && (double)v <= g_searchHigh));
                        if (match) e.value.val2Byte = v;
                    } break;

                    case DATA_4BYTE: {
                        uint32_t v = *reinterpret_cast<uint32_t*>(buf.data() + j);
                        match = (searchMode == SEARCH_UNKNOWN_INITIAL)
                            || (searchMode == SEARCH_EXACT && (double)v == searchVal)
                            || (searchMode == SEARCH_BIGGER && (double)v > searchVal)
                            || (searchMode == SEARCH_SMALLER && (double)v < searchVal)
                            || (searchMode == SEARCH_BETWEEN && ((double)v >= g_searchLow && (double)v <= g_searchHigh));
                        if (match) e.value.val4Byte = v;
                    } break;

                    case DATA_8BYTE: {
                        uint64_t v = *reinterpret_cast<uint64_t*>(buf.data() + j);
                        match = (searchMode == SEARCH_UNKNOWN_INITIAL)
                            || (searchMode == SEARCH_EXACT && (double)v == searchVal)
                            || (searchMode == SEARCH_BIGGER && (double)v > searchVal)
                            || (searchMode == SEARCH_SMALLER && (double)v < searchVal)
                            || (searchMode == SEARCH_BETWEEN && ((double)v >= g_searchLow && (double)v <= g_searchHigh));
                        if (match) e.value.val8Byte = v;
                    } break;

                    case DATA_FLOAT: {
                        float v = *reinterpret_cast<float*>(buf.data() + j);
                        match = (searchMode == SEARCH_UNKNOWN_INITIAL)
                            || (searchMode == SEARCH_EXACT && fabs((double)v - searchVal) < epsilon_float)
                            || (searchMode == SEARCH_BIGGER && (double)v > searchVal)
                            || (searchMode == SEARCH_SMALLER && (double)v < searchVal)
                            || (searchMode == SEARCH_BETWEEN && ((double)v >= g_searchLow && (double)v <= g_searchHigh));
                        if (match) {
                            if (v == 0.0f)
                                v = 0.0f;
                            e.value.valFloat = v;
                        }
                    } break;

                    case DATA_DOUBLE: {
                        double v = *reinterpret_cast<double*>(buf.data() + j);
                        match = (searchMode == SEARCH_UNKNOWN_INITIAL)
                            || (searchMode == SEARCH_EXACT && fabs(v - searchVal) < epsilon_double)
                            || (searchMode == SEARCH_BIGGER && v > searchVal)
                            || (searchMode == SEARCH_SMALLER && v < searchVal)
                            || (searchMode == SEARCH_BETWEEN && (v >= g_searchLow && v <= g_searchHigh));
                        if (match) {
                            if (v == 0.0)
                                v = 0.0;
                            e.value.valDouble = v;
                        }
                    } break;
                    }
                    if (match && g_candidateCount.load() < MAX_UNKNOWN_CANDIDATES)
                    {
                        out.push_back(e);
                        g_candidateCount.fetch_add(1);
                    }
                }
            }
            bytesScanned.fetch_add(mr.size);
        }
    };

    size_t offset = 0;
    for (unsigned t = 0; t < numThreads; ++t)
    {
        size_t cnt = perThread + (t < rem ? 1 : 0);
        workers.emplace_back(worker, offset, offset + cnt, t);
        offset += cnt;
    }

    const size_t interval = std::max<size_t>(1, totalBytes / 200);
    size_t last = 0;
    while (bytesScanned.load() < totalBytes)
    {
        size_t done = bytesScanned.load();
        if (done - last >= interval)
        {
            int pct = int((done * 100) / totalBytes);
            SendMessage(g_hProgressBar, PBM_SETPOS, pct, 0);
            UpdateWindow(g_hProgressBar);
            last = done;
        }
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(1);
    }
    for (auto& th : workers) th.join();
    SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
    UpdateWindow(g_hProgressBar);

    for (auto& vec : results)
        for (auto& e : vec)
            g_scanPager->Append(e);

    g_firstScanEntries.clear();
    g_previousScanEntries.clear();
    size_t tot = g_scanPager->Count();
    g_firstScanEntries.reserve(tot);
    g_previousScanEntries.reserve(tot);
    for (size_t i = 0; i < tot; ++i)
    {
        ScanEntry e;
        if (g_scanPager->GetEntry(i, e))
        {
            g_firstScanEntries.push_back(e);
            g_previousScanEntries.push_back(e);
        }
    }

    UpdateScanResultsListView();
    UpdateScanButtons(true);
    return true;
}

bool PerformNextScan(double searchVal, DataType dt, SearchMode searchMode)
{
    HANDLE hProcess = g_hTargetProcess;

    if (searchMode == SEARCH_CHANGED)
    {
        if (g_previousScanEntries.empty())
        {
            MessageBox(g_hWndMain,
                L"A previous scan must be performed before using 'Changed Value'.",
                L"Error", MB_OK | MB_ICONERROR);
            return false;
        }

        // Prepare a new pager for results
        ScanResultPager* newPager = new ScanResultPager(
            g_scanResultsFolder,
            MAPPED_PAGE_ENTRIES,
            ++g_currentScanId
        );

        // Iterate all previous candidates
        for (size_t i = 0; i < g_previousScanEntries.size(); ++i)
        {
            const ScanEntry& prev = g_previousScanEntries[i];
            ScanEntry curr = prev;
            bool valid = false;

            switch (dt)
            {
            case DATA_BYTE:
            {
                uint8_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)prev.address, &v, sizeof(v), nullptr))
                {
                    if (v != prev.value.valByte) valid = true;
                    curr.value.valByte = v;
                }
            } break;

            case DATA_2BYTE:
            {
                uint16_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)prev.address, &v, sizeof(v), nullptr))
                {
                    if (v != prev.value.val2Byte) valid = true;
                    curr.value.val2Byte = v;
                }
            } break;

            case DATA_4BYTE:
            {
                uint32_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)prev.address, &v, sizeof(v), nullptr))
                {
                    if (v != prev.value.val4Byte) valid = true;
                    curr.value.val4Byte = v;
                }
            } break;

            case DATA_8BYTE:
            {
                uint64_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)prev.address, &v, sizeof(v), nullptr))
                {
                    if (v != prev.value.val8Byte) valid = true;
                    curr.value.val8Byte = v;
                }
            } break;

            case DATA_FLOAT:
            {
                float v = 0.0f;
                if (ReadProcessMemory(hProcess, (LPCVOID)prev.address, &v, sizeof(v), nullptr))
                {
                    if (fabs(v - prev.value.valFloat) > epsilon_float) valid = true;
                    curr.value.valFloat = v;
                }
            } break;

            case DATA_DOUBLE:
            {
                double v = 0.0;
                if (ReadProcessMemory(hProcess, (LPCVOID)prev.address, &v, sizeof(v), nullptr))
                {
                    if (fabs(v - prev.value.valDouble) > epsilon_double) valid = true;
                    curr.value.valDouble = v;
                }
            } break;

            default:
                break;
            }

            if (valid)
            {
                newPager->Append(curr);
            }
        }

        // Push old pager onto undo stack and replace
        g_undoStack.push_back(g_scanPager);
        g_scanPager = newPager;

        // Rebuild previous‐scan entries
        g_previousScanEntries.clear();
        size_t total = g_scanPager->Count();
        g_previousScanEntries.reserve(total);
        for (size_t i = 0; i < total; ++i)
        {
            ScanEntry e;
            if (g_scanPager->GetEntry(i, e))
                g_previousScanEntries.push_back(e);
        }

        // Refresh UI
        UpdateScanResultsListView();
        return true;
    }

    if (searchMode == SEARCH_UNCHANGED)
    {
        if (g_previousScanEntries.empty())
        {
            MessageBox(g_hWndMain, L"A previous scan must be performed for the 'Unchanged Value' search.",
                L"Error", MB_OK | MB_ICONERROR);
            return false;
        }
        ScanResultPager* newPager = new ScanResultPager(g_scanResultsFolder, MAPPED_PAGE_ENTRIES, ++g_currentScanId);
        const size_t totalCandidates = g_previousScanEntries.size();
        for (size_t i = 0; i < totalCandidates; i++)
        {
            ScanEntry prevCandidate = g_previousScanEntries[i];
            ScanEntry newCandidate = prevCandidate;
            bool valid = false;

            if (dt == DATA_BYTE)
            {
                uint8_t val = 0;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(prevCandidate.address), &val, sizeof(val), nullptr))
                {
                    if (val == prevCandidate.value.valByte)
                        valid = true;
                    newCandidate.value.valByte = val;
                }
            }
            else if (dt == DATA_2BYTE)
            {
                uint16_t val = 0;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(prevCandidate.address), &val, sizeof(val), nullptr))
                {
                    if (val == prevCandidate.value.val2Byte)
                        valid = true;
                    newCandidate.value.val2Byte = val;
                }
            }
            else if (dt == DATA_4BYTE)
            {
                uint32_t val = 0;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(prevCandidate.address), &val, sizeof(val), nullptr))
                {
                    if (val == prevCandidate.value.val4Byte)
                        valid = true;
                    newCandidate.value.val4Byte = val;
                }
            }
            else if (dt == DATA_8BYTE)
            {
                uint64_t val = 0;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(prevCandidate.address), &val, sizeof(val), nullptr))
                {
                    if (val == prevCandidate.value.val8Byte)
                        valid = true;
                    newCandidate.value.val8Byte = val;
                }
            }
            else if (dt == DATA_FLOAT)
            {
                float val = 0;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(prevCandidate.address), &val, sizeof(val), nullptr))
                {
                    if (fabs(val - prevCandidate.value.valFloat) < epsilon_float)
                        valid = true;
                    newCandidate.value.valFloat = val;
                }
            }
            else if (dt == DATA_DOUBLE)
            {
                double val = 0;
                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(prevCandidate.address), &val, sizeof(val), nullptr))
                {
                    if (fabs(val - prevCandidate.value.valDouble) < epsilon_double)
                        valid = true;
                    newCandidate.value.valDouble = val;
                }
            }
            if (valid)
                newPager->Append(newCandidate);

            if (i % 1000 == 0)
            {
                int progress = static_cast<int>((i * 100) / totalCandidates);
                SendMessage(g_hProgressBar, PBM_SETPOS, progress, 0);
                UpdateWindow(g_hProgressBar);
                MSG tempMsg;
                while (PeekMessage(&tempMsg, NULL, 0, 0, PM_REMOVE))
                {
                    TranslateMessage(&tempMsg);
                    DispatchMessage(&tempMsg);
                }
            }
        }
        SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
        UpdateWindow(g_hProgressBar);

        g_undoStack.push_back(g_scanPager);
        g_scanPager = newPager;

        g_previousScanEntries.clear();
        size_t total = g_scanPager->Count();
        for (size_t i = 0; i < total; i++)
        {
            ScanEntry entry = { 0 };
            if (g_scanPager->GetEntry(i, entry))
                g_previousScanEntries.push_back(entry);
        }

        UpdateScanResultsListView();
        return true;
    }

    LONG_PTR origStyle = GetWindowLongPtr(g_hProgressBar, GWL_STYLE);
    SetWindowLongPtr(
        g_hProgressBar,
        GWL_STYLE,
        origStyle | PBS_MARQUEE
    );

    EnableWindow(g_hWndMain, FALSE);
    SendMessage(g_hProgressBar, PBM_SETMARQUEE, TRUE, 30);
    UpdateWindow(g_hProgressBar);

    MSG msg;
    std::unordered_map<uintptr_t, ScanEntry> prevMap;
    prevMap.reserve(g_previousScanEntries.size());
    for (size_t i = 0; i < g_previousScanEntries.size(); ++i)
    {
        const auto& e = g_previousScanEntries[i];
        prevMap[e.address] = e;

        if (i % 1000 == 0)
        {
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }

    ScanResultPager* newPager = new ScanResultPager(g_scanResultsFolder, MAPPED_PAGE_ENTRIES, ++g_currentScanId);

    SendMessage(g_hProgressBar, PBM_SETMARQUEE, FALSE, 0);
    SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
    UpdateWindow(g_hProgressBar);
    EnableWindow(g_hWndMain, TRUE);

    SetWindowLongPtr(
        g_hProgressBar,
        GWL_STYLE,
        origStyle
    );

    size_t totalCount = g_scanPager->Count();
    unsigned numThreads = std::thread::hardware_concurrency();
    if (!numThreads) numThreads = 2;
    size_t chunk = totalCount / numThreads;
    size_t rem = totalCount % numThreads;

    std::vector<std::vector<ScanEntry>> results(numThreads);
    std::atomic<size_t> processed{ 0 };
    std::vector<std::thread> workers;

    auto worker = [&](size_t start, size_t end, size_t idx) {
        auto& out = results[idx];
        for (size_t i = start; i < end; ++i)
        {
            ScanEntry e;
            if (!g_scanPager->GetEntry(i, e)) { processed.fetch_add(1); continue; }
            auto it = prevMap.find(e.address);
            if (it == prevMap.end()) { processed.fetch_add(1); continue; }
            const ScanEntry& prev = it->second;
            bool valid = false;

            switch (dt)
            {
            case DATA_BYTE: {
                uint8_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)e.address, &v, sizeof(v), nullptr))
                {
                    double c = v, p = prev.value.valByte;
                    if ((searchMode == SEARCH_INCREASED && c > p) ||
                        (searchMode == SEARCH_DECREASED && c < p) ||
                        (searchMode == SEARCH_EXACT && c == searchVal) ||
                        (searchMode == SEARCH_BIGGER && c > searchVal) ||
                        (searchMode == SEARCH_SMALLER && c < searchVal) ||
                        (searchMode == SEARCH_BETWEEN && (c >= g_searchLow && c <= g_searchHigh)))
                    {
                        valid = true;
                        e.value.valByte = v;
                    }
                }
            } break;
            case DATA_2BYTE: {
                uint16_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)e.address, &v, sizeof(v), nullptr))
                {
                    double c = v, p = prev.value.val2Byte;
                    if ((searchMode == SEARCH_INCREASED && c > p) ||
                        (searchMode == SEARCH_DECREASED && c < p) ||
                        (searchMode == SEARCH_EXACT && c == searchVal) ||
                        (searchMode == SEARCH_BIGGER && c > searchVal) ||
                        (searchMode == SEARCH_SMALLER && c < searchVal) ||
                        (searchMode == SEARCH_BETWEEN && (c >= g_searchLow && c <= g_searchHigh)))
                    {
                        valid = true;
                        e.value.val2Byte = v;
                    }
                }
            } break;
            case DATA_4BYTE: {
                uint32_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)e.address, &v, sizeof(v), nullptr))
                {
                    double c = v, p = prev.value.val4Byte;
                    if ((searchMode == SEARCH_INCREASED && c > p) ||
                        (searchMode == SEARCH_DECREASED && c < p) ||
                        (searchMode == SEARCH_EXACT && c == searchVal) ||
                        (searchMode == SEARCH_BIGGER && c > searchVal) ||
                        (searchMode == SEARCH_SMALLER && c < searchVal) ||
                        (searchMode == SEARCH_BETWEEN && (c >= g_searchLow && c <= g_searchHigh)))
                    {
                        valid = true;
                        e.value.val4Byte = v;
                    }
                }
            } break;
            case DATA_8BYTE: {
                uint64_t v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)e.address, &v, sizeof(v), nullptr))
                {
                    double c = (double)v, p = (double)prev.value.val8Byte;
                    if ((searchMode == SEARCH_INCREASED && c > p) ||
                        (searchMode == SEARCH_DECREASED && c < p) ||
                        (searchMode == SEARCH_EXACT && c == searchVal) ||
                        (searchMode == SEARCH_BIGGER && c > searchVal) ||
                        (searchMode == SEARCH_SMALLER && c < searchVal) ||
                        (searchMode == SEARCH_BETWEEN && (c >= g_searchLow && c <= g_searchHigh)))
                    {
                        valid = true;
                        e.value.val8Byte = v;
                    }
                }
            } break;
            case DATA_FLOAT: {
                float v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)e.address, &v, sizeof(v), nullptr)) {
                    double c = v;
                    double p = prev.value.valFloat;
                    double delta = c - p;

                    if ((searchMode == SEARCH_INCREASED && delta > epsilon_float) ||
                        (searchMode == SEARCH_DECREASED && delta < -epsilon_float) ||
                        (searchMode == SEARCH_EXACT && fabs(c - searchVal) < epsilon_float) ||
                        (searchMode == SEARCH_BIGGER && c > searchVal) ||
                        (searchMode == SEARCH_SMALLER && c < searchVal) ||
                        (searchMode == SEARCH_BETWEEN && (c >= g_searchLow && c <= g_searchHigh)))
                    {
                        valid = true;
                        if (v == 0.0f)
                            v = 0.0f;
                        e.value.valFloat = v;
                    }
                }
            } break;

            case DATA_DOUBLE: {
                double v = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)e.address, &v, sizeof(v), nullptr)) {
                    double c = v;
                    double p = prev.value.valDouble;
                    double delta = c - p;

                    if ((searchMode == SEARCH_INCREASED && delta > epsilon_double) ||
                        (searchMode == SEARCH_DECREASED && delta < -epsilon_double) ||
                        (searchMode == SEARCH_EXACT && fabs(c - searchVal) < epsilon_double) ||
                        (searchMode == SEARCH_BIGGER && c > searchVal) ||
                        (searchMode == SEARCH_SMALLER && c < searchVal) ||
                        (searchMode == SEARCH_BETWEEN && (c >= g_searchLow && c <= g_searchHigh)))
                    {
                        valid = true;
                        if (v == 0.0)
                            v = 0.0;
                        e.value.valDouble = v;
                    }
                }
            } break;
            }

            if (valid) out.push_back(e);
            processed.fetch_add(1);
        }
    };

    size_t off = 0;
    for (unsigned t = 0; t < numThreads; ++t)
    {
        size_t cnt = chunk + (t < rem ? 1 : 0);
        workers.emplace_back(worker, off, off + cnt, t);
        off += cnt;
    }

    const size_t interval = std::max<size_t>(1, totalCount / 200);
    size_t last = 0;
    while (processed.load() < totalCount)
    {
        size_t done = processed.load();
        if (done - last >= interval)
        {
            int pct = int((done * 100) / totalCount);
            SendMessage(g_hProgressBar, PBM_SETPOS, pct, 0);
            UpdateWindow(g_hProgressBar);
            last = done;
        }
        MSG msg2;
        while (PeekMessage(&msg2, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg2);
            DispatchMessage(&msg2);
        }
        Sleep(1);
    }

    for (auto& th : workers) th.join();
    SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
    UpdateWindow(g_hProgressBar);

    for (auto& vec : results)
        for (auto& e : vec)
            newPager->Append(e);
    g_undoStack.push_back(g_scanPager);
    g_scanPager = newPager;
    g_previousScanEntries.clear();
    size_t tot = g_scanPager->Count();
    g_previousScanEntries.reserve(tot);
    for (size_t i = 0; i < tot; ++i)
    {
        ScanEntry e;
        if (g_scanPager->GetEntry(i, e))
            g_previousScanEntries.push_back(e);
    }

    UpdateScanResultsListView();
    return true;
}

bool UndoScan()
{
    if (!g_undoStack.empty())
    {
        delete g_scanPager;
        g_scanPager = g_undoStack.back();
        g_undoStack.pop_back();
        UpdateScanResultsListView();
        return true;
    }
    return false;
}

void ResetScans()
{
    if (g_scanPager) { delete g_scanPager; g_scanPager = nullptr; }
    for (auto pager : g_undoStack) delete pager;
    g_undoStack.clear();
    g_initialScanCount = 0;
    ListView_DeleteAllItems(g_hListScanResults);
    g_lastDisplayedEntries.clear();
    g_itemChanged.clear();
    g_firstScanEntries.clear();
    g_previousScanEntries.clear();
}

void UpdateScanStatus()
{
    size_t total = (g_scanPager ? g_scanPager->Count() : 0);
    size_t displayCount = (total > DISPLAY_LIMIT ? DISPLAY_LIMIT : total);
    std::wstring statusText = L"Displaying " + FormatNumberWithCommas(displayCount) +
        L" values out of " + FormatNumberWithCommas(total);
    SetWindowText(g_hStaticScanStatus, statusText.c_str());
}

void UpdateScanResultsListView()
{
    ListView_DeleteAllItems(g_hListScanResults);
    g_lastDisplayedEntries.clear();
    g_itemChanged.clear();

    int index = 0;
    size_t total = (g_scanPager ? g_scanPager->Count() : 0);
    size_t limit = (total > DISPLAY_LIMIT ? DISPLAY_LIMIT : total);

    for (size_t i = 0; i < limit; i++)
    {
        ScanEntry entry = { 0 };

        if (!g_scanPager->GetEntry(i, entry))
            continue;

        if (entry.address <= 0xFFFFFF)
            continue;

        wchar_t addressStr[32];
        swprintf(addressStr, 32, L"%llX", (unsigned long long)entry.address);

        wchar_t currValueStr[64] = { 0 };
        switch (entry.dataType)
        {
        case DATA_BYTE:   swprintf(currValueStr, 64, L"%u", entry.value.valByte); break;
        case DATA_2BYTE:  swprintf(currValueStr, 64, L"%u", entry.value.val2Byte); break;
        case DATA_4BYTE:  swprintf(currValueStr, 64, L"%u", entry.value.val4Byte); break;
        case DATA_8BYTE:  swprintf(currValueStr, 64, L"%llu", entry.value.val8Byte); break;
        case DATA_FLOAT:  swprintf(currValueStr, 64, L"%.4f", entry.value.valFloat); break;
        case DATA_DOUBLE: swprintf(currValueStr, 64, L"%.4f", entry.value.valDouble); break;
        default: swprintf(currValueStr, 64, L"Unknown"); break;
        }

        wchar_t prevValueStr[64] = { 0 };
        if (i < g_previousScanEntries.size())
        {
            ScanEntry prevEntry = g_previousScanEntries[i];
            switch (prevEntry.dataType)
            {
            case DATA_BYTE:   swprintf(prevValueStr, 64, L"%u", prevEntry.value.valByte); break;
            case DATA_2BYTE:  swprintf(prevValueStr, 64, L"%u", prevEntry.value.val2Byte); break;
            case DATA_4BYTE:  swprintf(prevValueStr, 64, L"%u", prevEntry.value.val4Byte); break;
            case DATA_8BYTE:  swprintf(prevValueStr, 64, L"%llu", prevEntry.value.val8Byte); break;
            case DATA_FLOAT:  swprintf(prevValueStr, 64, L"%.4f", prevEntry.value.valFloat); break;
            case DATA_DOUBLE: swprintf(prevValueStr, 64, L"%.4f", prevEntry.value.valDouble); break;
            default: swprintf(prevValueStr, 64, L"Unknown"); break;
            }
        }
        else
        {
            wcscpy_s(prevValueStr, currValueStr);
        }

        wchar_t firstValueStr[64] = { 0 };
        if (i < g_firstScanEntries.size())
        {
            ScanEntry firstEntry = g_firstScanEntries[i];
            switch (firstEntry.dataType)
            {
            case DATA_BYTE:   swprintf(firstValueStr, 64, L"%u", firstEntry.value.valByte); break;
            case DATA_2BYTE:  swprintf(firstValueStr, 64, L"%u", firstEntry.value.val2Byte); break;
            case DATA_4BYTE:  swprintf(firstValueStr, 64, L"%u", firstEntry.value.val4Byte); break;
            case DATA_8BYTE:  swprintf(firstValueStr, 64, L"%llu", firstEntry.value.val8Byte); break;
            case DATA_FLOAT:  swprintf(firstValueStr, 64, L"%.4f", firstEntry.value.valFloat); break;
            case DATA_DOUBLE: swprintf(firstValueStr, 64, L"%.4f", firstEntry.value.valDouble); break;
            default: swprintf(firstValueStr, 64, L"Unknown"); break;
            }
        }
        else
        {
            wcscpy_s(firstValueStr, currValueStr);
        }

        LVITEM lvItem = { 0 };
        lvItem.mask = LVIF_TEXT;
        lvItem.iItem = index;
        lvItem.pszText = addressStr;
        int itemIndex = ListView_InsertItem(g_hListScanResults, &lvItem);
        ListView_SetItemText(g_hListScanResults, itemIndex, 1, currValueStr);
        ListView_SetItemText(g_hListScanResults, itemIndex, 2, prevValueStr);
        ListView_SetItemText(g_hListScanResults, itemIndex, 3, firstValueStr);

        g_lastDisplayedEntries.push_back(entry);
        g_itemChanged.push_back(false);

        index++;
    }
    UpdateScanStatus();
}

DWORD WINAPI PointerScanThreadProc(LPVOID lpParam)
{
    wchar_t modulePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(g_hModule, modulePath, MAX_PATH);
    std::wstring moduleDir(modulePath);
    size_t pos = moduleDir.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        moduleDir.resize(pos);

    // 2) Build "<DLL‑dir>\Pointers"
    std::wstring pointersDir = moduleDir + L"\\Pointers";

    // 3) Create it if it doesn't exist
    DWORD dirAttr = GetFileAttributesW(pointersDir.c_str());
    if (dirAttr == INVALID_FILE_ATTRIBUTES
        || !(dirAttr & FILE_ATTRIBUTE_DIRECTORY))
    {
        CreateDirectoryW(pointersDir.c_str(), nullptr);
    }

    // 0) Unpack parameters
    auto* sp = static_cast<PointerScanParams*>(lpParam);
    uintptr_t baseAddr = sp->baseAddr;
    uintptr_t dynamicAddr = sp->dynamicAddr;
    int       maxDepth = sp->maxDepth;
    delete sp;

    g_stopPointerScan = false;
    g_isPointerScanning = true;
    AppendConsoleAsync("Scan started...\r\n");

    char baseHigh = GetHighHexDigit(baseAddr);
    std::vector<char> allowedHigh = { baseHigh };

    // 1) Follow any existing positional offsets
    std::vector<DWORD_PTR> initial = g_positionalOffsets;
    std::vector<DWORD_PTR> used = initial;
    uintptr_t currentPtr = baseAddr;
    bool      initialFail = false;
    for (auto off : initial) {
        uintptr_t val = 0;
        if (!SafeReadPtr(currentPtr + off, &val)) {
            initialFail = true;
            break;
        }
        currentPtr = val;
    }
    if (!initialFail && currentPtr == dynamicAddr) {
        AppendConsoleAsync("Scan Finished (matched existing offsets).\r\n\r\n");
        g_isPointerScanning = false;
        return 0;
    }
    if (initialFail) {
        AppendConsoleAsync("Failed initial chain; continuing brute‑force.\r\n");
    }

    // 2) BFS brute‑force, collecting _all_ matching chains :contentReference[oaicite:1]{index=1}
    struct Node { uintptr_t ptr; int depth; std::vector<DWORD_PTR> offs; };
    std::queue<Node> q;
    std::unordered_set<uintptr_t> visited;
    visited.insert(currentPtr);
    q.push({ currentPtr, (int)initial.size(), used });

    std::vector<std::vector<DWORD_PTR>> allResults;
    int lastLogDepth = -1;

    while (!q.empty() && !g_stopPointerScan) {
        Node node = q.front(); q.pop();
        if (node.depth >= maxDepth) continue;

        // depth‐based progress logging
        if (node.depth != lastLogDepth) {
            char buf[128];
            sprintf_s(buf, sizeof(buf),
                "Scanning For 0x%llX | Depth %d\r\n",
                (unsigned long long)dynamicAddr,
                node.depth);
            AppendConsoleAsync(buf);
            lastLogDepth = node.depth;
        }

        // try every offset step
        for (DWORD_PTR off = 0; off <= MAX_OFFSET && !g_stopPointerScan; off += OFFSET_STEP) {
            uintptr_t addr = node.ptr + off;
            uintptr_t val = 0;

            if (!SafeReadPtr(addr, &val)) continue;

            if (!IsAllowedAddress(val, allowedHigh)) continue;

            // exact match?
            if (val == dynamicAddr) {
                auto chain = node.offs;
                chain.push_back(off);
                allResults.push_back(std::move(chain));
                continue;
            }

            // sub‑offset?
            if (val != 0 && dynamicAddr > val) {
                DWORD_PTR diff = dynamicAddr - val;
                if (diff <= MAX_SUBOFFSET) {
                    auto chain = node.offs;
                    chain.push_back(off);
                    chain.push_back(diff);
                    allResults.push_back(std::move(chain));
                    continue;
                }
            }

            // enqueue further if readable and unseen
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(g_hTargetProcess, (LPCVOID)val, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT &&
                IsReadable(mbi.Protect) &&
                !visited.count(val))
            {
                visited.insert(val);
                Node next = node;
                next.ptr = val;
                next.depth = node.depth + 1;
                next.offs.push_back(off);
                q.push(std::move(next));
            }
        }
    }

    // 3) Finish up
    if (!allResults.empty()) {
        // Figure out a sane default file name
        wchar_t fullPath[MAX_PATH]{};
        DWORD   len = MAX_PATH;
        if (QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &len)) {
            wchar_t* exeName = wcsrchr(fullPath, L'\\');
            exeName = exeName ? exeName + 1 : fullPath;
            std::wstring name(exeName);
            if (auto dot = name.find_last_of(L'.'); dot != std::wstring::npos)
                name.resize(dot);

            // build default path: Pointers\<ProcessName>.MPTR
            wchar_t defaultPath[MAX_PATH] = { 0 };
            wsprintfW(defaultPath,
                L"%s\\%s.MPTR",
                pointersDir.c_str(),
                name.c_str());

            OPENFILENAMEW ofn{ sizeof(ofn) };
            wchar_t szFile[MAX_PATH] = { 0 };
            wcscpy_s(szFile, defaultPath);

            ofn.hwndOwner = g_hWndMain;
            ofn.lpstrFilter = L"Pointer files (*.MPTR)\0*.MPTR\0All Files\0*.*\0\0";
            ofn.lpstrFile = szFile;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrDefExt = L"MPTR";
            ofn.lpstrInitialDir = pointersDir.c_str();
            ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

            if (GetSaveFileNameW(&ofn)) {
                std::wofstream ofs(ofn.lpstrFile, std::ios::trunc);

                // Grab the module name and base address
                wchar_t moduleName[MAX_PATH] = { 0 };
                uintptr_t moduleBase = 0;
                {
                    HMODULE hMods[1];
                    DWORD cbNeeded = 0;
                    if (EnumProcessModules(g_hTargetProcess, hMods, sizeof(hMods), &cbNeeded)) {
                        GetModuleBaseNameW(g_hTargetProcess, hMods[0], moduleName, MAX_PATH);
                        MODULEINFO mi{};
                        GetModuleInformation(g_hTargetProcess, hMods[0], &mi, sizeof(mi));
                        moduleBase = (uintptr_t)mi.lpBaseOfDll;
                    }
                }

                // For each pointer‐chain, compute and write baseExpr + offsets
                for (auto& chain : allResults) {
                    std::wstring baseExpr;
                    if (g_unrealDetected) {
                        uintptr_t rva = g_resolvedBaseAddress - moduleBase;
                        wchar_t buf[128];
                        swprintf(buf, _countof(buf),
                            L"%s+%llX",
                            moduleName,
                            (unsigned long long)rva);
                        baseExpr = buf;
                    }
                    else {
                        // read hex string out of the base‑address edit box
                        wchar_t buf[64] = { 0 };
                        GetWindowTextW(g_hEditBaseAddress, buf, _countof(buf));
                        baseExpr = buf;
                    }

                    // write it
                    ofs << baseExpr;

                    // then the pointer offsets
                    for (size_t i = 0; i < chain.size(); ++i) {
                        ofs << L',' << std::hex << chain[i];
                    }
                    ofs << L'\n';
                }

                ofs.close();

                if (g_stopPointerScan) {
                    AppendConsoleAsync("Scan Stopped... Partial results saved.\r\n\r\n");
                }
                else {
                    AppendConsoleAsync("Scan Complete.\r\n\r\n");
                }
            }
            else {
                AppendConsoleAsync("No file chosen; scan results discarded.\r\n\r\n");
            }
        }
    }
    else {
        AppendConsoleAsync("No pointer chains found.\r\n\r\n");
    }

    g_isPointerScanning = false;
    return 0;
}


//===========================================================================
// Enumeration Callbacks
//===========================================================================
BOOL CALLBACK EnumApplicationsProcW(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd)) return TRUE;
    if (GetWindow(hwnd, GW_OWNER) != NULL) return TRUE;
    int len = GetWindowTextLengthW(hwnd);
    if (len == 0) return TRUE;
    wchar_t title[256];
    GetWindowTextW(hwnd, title, 256);
    if (wcscmp(title, L"Program Manager") == 0) return TRUE;
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    HWND hList = (HWND)lParam;
    wchar_t item[512];
    swprintf_s(item, 512, L"%s (PID: %d)", title, pid);
    int index = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)item);
    SendMessageW(hList, LB_SETITEMDATA, index, (LPARAM)pid);
    return TRUE;
}

BOOL CALLBACK EnumWindowsWindowsProcW(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd)) return TRUE;
    int len = GetWindowTextLengthW(hwnd);
    if (len == 0) return TRUE;
    wchar_t title[256];
    GetWindowTextW(hwnd, title, 256);
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    HWND hList = (HWND)lParam;
    wchar_t item[512];
    swprintf_s(item, 512, L"%s (PID: %d)", title, pid);
    int index = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)item);
    SendMessageW(hList, LB_SETITEMDATA, index, (LPARAM)pid);
    return TRUE;
}


//===========================================================================
// Process Selection Dialog
//===========================================================================
LRESULT CALLBACK ProcessDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HWND hTab = NULL, hList = NULL;
    switch (message)
    {
    case WM_CREATE:
    {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        hTab = CreateWindowExW(0, WC_TABCONTROL, L"", WS_CHILD | WS_VISIBLE | TCS_TABS, 10, 5, 320, 25, hDlg, (HMENU)IDC_FILTER_TAB, hInst, NULL);
        TCITEMW tie = { 0 };
        tie.mask = TCIF_TEXT;
        tie.pszText = const_cast<LPWSTR>(L"Applications");
        TabCtrl_InsertItem(hTab, 0, &tie);
        tie.pszText = const_cast<LPWSTR>(L"Processes");
        TabCtrl_InsertItem(hTab, 1, &tie);
        tie.pszText = const_cast<LPWSTR>(L"Windows");
        TabCtrl_InsertItem(hTab, 2, &tie);
        hList = CreateWindowW(L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOTIFY | WS_VSCROLL, 10, 35, 320, 360, hDlg, (HMENU)IDC_PROCESS_LIST, hInst, NULL);
        SendMessageW(hList, LB_RESETCONTENT, 0, 0);
        EnumWindows(EnumApplicationsProcW, (LPARAM)hList);
        SendMessageW(hList, LB_SETCURSEL, 0, 0);
        SetForegroundWindow(hList);
        SetFocus(hList);
    }
    break;
    case WM_NOTIFY:
    {
        NMHDR* nmhdr = (NMHDR*)lParam;
        if (nmhdr->hwndFrom == GetDlgItem(hDlg, IDC_FILTER_TAB))
        {
            if (nmhdr->code == TCN_SELCHANGE)
            {
                int sel = TabCtrl_GetCurSel(GetDlgItem(hDlg, IDC_FILTER_TAB));
                SendMessageW(hList, LB_RESETCONTENT, 0, 0);
                if (sel == 0)
                    EnumWindows(EnumApplicationsProcW, (LPARAM)hList);
                else if (sel == 1)
                {
                    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnap != INVALID_HANDLE_VALUE)
                    {
                        PROCESSENTRY32W pe32;
                        pe32.dwSize = sizeof(PROCESSENTRY32W);
                        if (Process32FirstW(hSnap, &pe32))
                        {
                            do {
                                DWORD sessionId = 0;
                                ProcessIdToSessionId(pe32.th32ProcessID, &sessionId);
                                if (sessionId == 0)
                                    continue;
                                wchar_t item[512];
                                swprintf_s(item, 512, L"%s (PID: %d)", pe32.szExeFile, pe32.th32ProcessID);
                                int index = (int)SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)item);
                                SendMessageW(hList, LB_SETITEMDATA, index, (LPARAM)pe32.th32ProcessID);
                            } while (Process32NextW(hSnap, &pe32));
                        }
                        CloseHandle(hSnap);
                    }
                }
                else if (sel == 2)
                    EnumWindows(EnumWindowsWindowsProcW, (LPARAM)hList);
                SendMessageW(hList, LB_SETCURSEL, 0, 0);
                return 0;
            }
        }
    }
    break;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_PROCESS_LIST && HIWORD(wParam) == LBN_DBLCLK)
        {
            int sel = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR)
                g_targetPID = (DWORD)SendMessageW(hList, LB_GETITEMDATA, sel, 0);
            DestroyWindow(hDlg);
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hDlg);
        return 0;
    default:
        return DefWindowProcW(hDlg, message, wParam, lParam);
    }
    return 0;
}

void SelectProcessDialog(HWND hParent)
{
    EnableWindow(hParent, FALSE);

    HINSTANCE hInst = GetModuleHandleW(NULL);
    static bool reg = false;
    if (!reg)
    {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = ProcessDialogProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"ProcessDialogClass";
        RegisterClassW(&wc);
        reg = true;
    }

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"ProcessDialogClass",
        L"Select Process",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 355, 447,
        hParent, NULL, hInst, NULL
    );
    if (!hDlg)
    {
        EnableWindow(hParent, TRUE);
        return;
    }

    RECT rcP, rcD;
    GetWindowRect(hParent, &rcP);
    GetWindowRect(hDlg, &rcD);
    int x = rcP.left + ((rcP.right - rcP.left) - (rcD.right - rcD.left)) / 2;
    int y = rcP.top + ((rcP.bottom - rcP.top) - (rcD.bottom - rcD.top)) / 2;
    SetWindowPos(hDlg, NULL, x, y, 0, 0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    SetFocus(hDlg);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        if (!IsDialogMessage(hDlg, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (!IsWindow(hDlg))
            break;
    }

    EnableWindow(hParent, TRUE);
    SetForegroundWindow(hParent);
}


//===========================================================================
// Injection & Attachment
//===========================================================================
static void InjectSelfIntoProcess(DWORD pid)
{
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(g_hModule, path, MAX_PATH)) {
        wprintf(L"GetModuleFileNameW failed: %lu\n", GetLastError());
        return;
    }
    SIZE_T len = (wcslen(path) + 1) * sizeof(wchar_t);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);

    if (!hProc) {
        wprintf(L"OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return;
    }

    LPVOID mem = VirtualAllocEx(
        hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!mem) {
        wprintf(L"VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return;
    }

    if (!WriteProcessMemory(hProc, mem, path, len, NULL)) {
        wprintf(L"WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }

    HANDLE hThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)LoadLibraryW,
        mem,
        0,
        NULL
    );
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
    CloseHandle(hProc);
}

static void AttachToProcess(DWORD pid)
{
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );
    if (!hProc) return;

    g_hOriginalProcess = g_hTargetProcess;
    g_originalProcessId = g_targetProcessId;
    g_hTargetProcess = hProc;
    g_targetProcessId = pid;
    g_isAttached = true;

    {
        HMENU hMenu = GetMenu(g_hWndMain);
        MENUITEMINFO mii{ sizeof(mii) };
        mii.fMask = MIIM_STRING;
        mii.dwTypeData = const_cast<LPWSTR>(L"Detach");
        SetMenuItemInfoW(hMenu, ID_MENU_ATTACH, FALSE, &mii);
    }

    {
        wchar_t fullPath[MAX_PATH]{};
        DWORD   len = MAX_PATH;
        QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &len);

        wchar_t* exePtr = wcsrchr(fullPath, L'\\');
        const wchar_t* exeNameBase = exePtr ? exePtr + 1 : fullPath;

        wchar_t info[128];
        swprintf(info, 128, L"%s (PID: %lu)", exeNameBase, pid);

        HMENU hMenu = GetMenu(g_hWndMain);
        MENUITEMINFO miiInfo{ sizeof(miiInfo) };
        miiInfo.fMask = MIIM_STRING;
        miiInfo.dwTypeData = info;
        SetMenuItemInfoW(hMenu, ID_MENU_PROCINFO, FALSE, &miiInfo);

        DrawMenuBar(g_hWndMain);

        std::wstring logLine =
            L"Attached to " + std::wstring(exeNameBase) +
            L" (PID: " + std::to_wstring(pid) + L")\r\n\r\n";
        Log(logLine.c_str());
    }

    ResolvePendingSavedEntries();

    {
        wchar_t fullPath[MAX_PATH]{};
        DWORD   len = MAX_PATH;
        QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &len);

        wchar_t* exePtr = wcsrchr(fullPath, L'\\');
        std::wstring exeName = exePtr ? (exePtr + 1) : fullPath;
        size_t dot = exeName.find_last_of(L'.');
        if (dot != std::wstring::npos)
            exeName.resize(dot);

        PromptLoadSavedTableForProcess(exeName);
    }

    {
        wchar_t fullPath[MAX_PATH]{};
        DWORD   len = MAX_PATH;
        QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &len);

        wchar_t* exePtr = wcsrchr(fullPath, L'\\');
        std::wstring exeName = exePtr ? (exePtr + 1) : fullPath;

        if (exeName.find(L"Win64-Shipping") != std::wstring::npos)
        {
            g_unrealDetected = true;
            Log(L"Unreal Game Detected\r\n");

            wchar_t fullPath[MAX_PATH];
            DWORD len = MAX_PATH;
            QueryFullProcessImageNameW(g_hTargetProcess, 0, fullPath, &len);

            std::string pathUtf8 = WideToAnsi(fullPath);
            std::string exeUtf8 = WideToAnsi(exeName);

            std::string ver = GetUnrealEngineVersion(pathUtf8, exeUtf8);
            if (ver.empty()) ver = "Unknown";

            std::wstring wver(ver.begin(), ver.end());
            wchar_t buf[128];
            swprintf(buf, 128, L"Unreal Engine Version: %s\r\n", wver.c_str());
            Log(buf);

            uint64_t rawRVA = 0;
            for (auto& sig : getSignatures())
                if (sig.name.find("GWorld") != std::string::npos &&
                    (rawRVA = findOffsetInProcessMemory(
                        g_hTargetProcess, sig.pattern, sig.mask, "GWorld")))
                    break;

            if (!rawRVA)
            {
                Log(L"Failed to locate GWorld offset\r\n\r\n");
            }
            else
            {
                HMODULE hMods[1];
                DWORD   cbNeeded = 0;
                if (EnumProcessModules(g_hTargetProcess, hMods, sizeof(hMods), &cbNeeded))
                {
                    MODULEINFO mi{};
                    GetModuleInformation(g_hTargetProcess, hMods[0], &mi, sizeof(mi));

                    uintptr_t moduleBase = (uintptr_t)mi.lpBaseOfDll;
                    uintptr_t ptrAddress = moduleBase + (uintptr_t)rawRVA;

                    {
                        wchar_t dbg[64];
                        swprintf(dbg, 64,
                            L"Base Address: 0x%llX\r\n",
                            (unsigned long long)ptrAddress);
                        Log(dbg);
                    }

                    uint64_t realGWorld = 0;
                    SIZE_T  bytesRead = 0;
                    if (ReadProcessMemory(
                        g_hTargetProcess,
                        (LPCVOID)ptrAddress,
                        &realGWorld,
                        sizeof(realGWorld),
                        &bytesRead
                    )
                        && bytesRead == sizeof(realGWorld)
                        )
                    {
                        // update the UI
                        wchar_t buf[32];
                        swprintf(buf, 32, L"%llX", (unsigned long long)ptrAddress);
                        if (!g_isPointerScanning) {
                            SetWindowTextW(g_hEditBaseAddress, buf);
                        }

                        g_resolvedBaseAddress = ptrAddress;

                        if (!InitGNames(g_hTargetProcess, moduleBase, ver)) {
                            Log(L"GNames init failed, descriptions will be unavailable\r\n");
                        }
                        SearchPositionalPointerPaths();

                        Log(L"\r\n");
                    }
                    else
                    {
                        Log(L"ReadProcessMemory for GWorld pointer failed\r\n\r\n");
                    }
                }
                else
                {
                    Log(L"EnumProcessModules failed\r\n\r\n");
                }
            }
        }
        else
        {
            g_unrealDetected = false;
        }
    }
}

static void TryResolveUnrealOnProcess(HANDLE hProcess)
{
    wchar_t procPath[MAX_PATH] = {};
    DWORD   len = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, procPath, &len))
        return;

    wchar_t* exePtr = wcsrchr(procPath, L'\\');
    std::wstring exeName = exePtr ? (exePtr + 1) : procPath;
    if (auto dot = exeName.find_last_of(L'.'); dot != std::wstring::npos)
        exeName.resize(dot);

    if (exeName.find(L"Win64-Shipping") == std::wstring::npos)
        return;

    uint64_t rawRVA = 0;
    for (auto& sig : getSignatures())
    {
        if (sig.name.find("GWorld") != std::string::npos)
        {
            rawRVA = findOffsetInProcessMemory(
                hProcess, sig.pattern, sig.mask, "GWorld");
            if (rawRVA) break;
        }
    }
    if (!rawRVA)
        return;

    HMODULE   hMods[1];
    DWORD     cbNeeded = 0;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return;

    MODULEINFO mi{};
    if (!GetModuleInformation(hProcess, hMods[0], &mi, sizeof(mi)))
        return;

    uintptr_t moduleBase = (uintptr_t)mi.lpBaseOfDll;
    uintptr_t ptrAddress = moduleBase + (uintptr_t)rawRVA;

    {
        wchar_t buf[32];
        swprintf(buf, 32, L"%llX", (unsigned long long)ptrAddress);
        if (!g_isPointerScanning) {
            SetWindowTextW(g_hEditBaseAddress, buf);
        }
    }

    uint64_t realGWorld = 0;
    SIZE_T  bytesRead = 0;
    if (!ReadProcessMemory(
        hProcess,
        (LPCVOID)ptrAddress,
        &realGWorld,
        sizeof(realGWorld),
        &bytesRead
    ) || bytesRead != sizeof(realGWorld))
    {
        return;
    }
    {
        wchar_t buf[32];
        swprintf(buf, 32, L"%llX", (unsigned long long)realGWorld);
        SetWindowTextW(g_hDynamicAddressEdit, buf);
    }

    g_resolvedBaseAddress = ptrAddress;

    g_unrealDetected = true;
    Log(L"Unreal Game Detected\r\n");
    SearchPositionalPointerPaths();
}

static void SearchPositionalPointerPaths()
{
    // Always start with Auto disabled
    EnableWindow(g_hBtnAutoOffset, FALSE);

    Log(L"\r\n +Scanning for Base‑Offset candidates…\r\n");

    // Grab the UWorld pointer
    HANDLE    hProc = g_hTargetProcess;
    uintptr_t worldPtr = g_resolvedBaseAddress;
    uintptr_t basePtr = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)worldPtr, &basePtr, sizeof(basePtr), nullptr))
    {
        Log(L" -Failed to read UWorld pointer\r\n\r\n");
        return;
    }

    g_autoOffsets.clear();
    constexpr uintptr_t START = 0x30, END = 0x300;
    int baseDigits = GetHexDigitCount(basePtr);

    for (uintptr_t off = START; off < END; off += sizeof(uintptr_t))
    {
        uintptr_t val = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(basePtr + off), &val, sizeof(val), nullptr) || !val)
            continue;

        if (GetHexDigitCount(val) != baseDigits)
            continue;

        g_autoOffsets.emplace_back(off, val);
    }

    {
        wchar_t buf[32];
        swprintf(buf, 32, L"%llX", (unsigned long long)basePtr);
        std::wstring prefix(buf);
        if (prefix.size() > 3) prefix.resize(3);

        g_autoOffsets.erase(
            std::remove_if(
                g_autoOffsets.begin(),
                g_autoOffsets.end(),
                [&](auto& p) {
            wchar_t vbuf[32];
            swprintf(vbuf, 32, L"%llX", (unsigned long long)p.second);
            return std::wstring(vbuf).rfind(prefix, 0) != 0;
        }
            ),
            g_autoOffsets.end()
        );
    }

    // Only enable Auto if we actually found candidates
    if (!g_autoOffsets.empty())
    {
        EnableWindow(g_hBtnAutoOffset, TRUE);
        Log(L" +Found " + std::to_wstring(g_autoOffsets.size()) +
            L" Possible Offsets\r\n"
            L" +Press Auto to view..\r\n\r\n");
    }
    else
    {
        Log(L" -No Possible Offset candidates found.\r\n\r\n");
    }
}


//===========================================================================
// Win32 Bootstrap & Main Loop
//===========================================================================
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COPYDATA:
        return Handle_CopyData(hWnd, lParam);

    case WM_CTLCOLORSTATIC:
        return Handle_CtlColorStatic(wParam, lParam);

    case WM_CREATE:
        return Handle_Create(hWnd, lParam);

    case WM_TIMER:
        return Handle_Timer(hWnd);

    case WM_NOTIFY:
        return Handle_Notify(hWnd, wParam, lParam);

    case WM_COMMAND:
        return Handle_Command(hWnd, wParam, lParam);

    case WM_DESTROY:
        return Handle_Destroy(hWnd);

    default:
        return DefWindowProcW(hWnd, message, wParam, lParam);
    }
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    HINSTANCE hInstance = (HINSTANCE)lpParam;
    HICON hIconLarge = LoadIconW(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    HICON hIconSmall = (HICON)LoadImageW(
        hInstance,
        MAKEINTRESOURCE(IDI_ICON1),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR
    );

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MemoryScannerClass";
    wc.hIcon = hIconLarge;
    wc.hIconSm = hIconSmall;
    RegisterClassExW(&wc);

    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW((HMODULE)lpParam, modulePath, MAX_PATH);
    std::wstring baseFolder(modulePath);
    size_t pos = baseFolder.find_last_of(L"\\\\/");
    if (pos != std::wstring::npos)
        baseFolder = baseFolder.substr(0, pos);

    g_scanResultsFolder = baseFolder + L"\\ScanResults";
    CreateDirectoryW(g_scanResultsFolder.c_str(), NULL);

    g_tablesFolder = baseFolder + L"\\Tables";
    CreateDirectoryW(g_tablesFolder.c_str(), NULL);

    CleanupDatFiles(g_scanResultsFolder);

    INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icex);

    g_hWndMain = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"MemRE",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        940, 540,
        nullptr, nullptr,
        hInstance,
        nullptr
    );

    SetWindowPos(g_hWndMain, NULL, 670, 340, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    LONG style = GetWindowLongW(g_hWndMain, GWL_STYLE);
    style &= ~WS_MAXIMIZEBOX;
    SetWindowLongW(g_hWndMain, GWL_STYLE, style);

    HMENU hSys = GetSystemMenu(g_hWndMain, FALSE);
    if (hSys)
        DeleteMenu(hSys, SC_CLOSE, MF_BYCOMMAND);

    ShowWindow(g_hWndMain, SW_SHOW);
    UpdateWindow(g_hWndMain);

    g_hTargetProcess = GetCurrentProcess();
    g_targetProcessId = GetCurrentProcessId();
    g_hOriginalProcess = g_hTargetProcess;
    g_originalProcessId = g_targetProcessId;

    {
        // figure out our own EXE name
        wchar_t fullPath[MAX_PATH] = {};
        DWORD   len = MAX_PATH;
        QueryFullProcessImageNameW(GetCurrentProcess(), 0, fullPath, &len);
        wchar_t* exePtr = wcsrchr(fullPath, L'\\');
        const wchar_t* exeName = exePtr ? exePtr + 1 : fullPath;

        if (_wcsicmp(exeName, L"MemRE.exe") != 0)
        {
            g_hTargetProcess = GetCurrentProcess();
            g_targetProcessId = GetCurrentProcessId();
            g_hOriginalProcess = g_hTargetProcess;
            g_originalProcessId = g_targetProcessId;
            //g_isAttached = true;

            ResolvePendingSavedEntries();

            std::wstring name(exeName);
            size_t dot = name.find_last_of(L'.');
            if (dot != std::wstring::npos)
                name.resize(dot);

            PromptLoadSavedTableForProcess(name);

            if (name.find(L"Win64-Shipping") != std::wstring::npos)
            {
                g_unrealDetected = true;
                Log(L"Unreal Game Detected\r\n");

                std::string pathUtf8 = WideToAnsi(fullPath);
                std::string exeUtf8 = WideToAnsi(name);
                std::string ver = GetUnrealEngineVersion(pathUtf8, exeUtf8);
                if (ver.empty()) ver = "Unknown";
                {
                    std::wstring wver(ver.begin(), ver.end());
                    wchar_t buf[128];
                    swprintf(buf, 128, L"Unreal Engine Version: %s\r\n", wver.c_str());
                    Log(buf);
                }

                uint64_t rawRVA = 0;
                for (auto& sig : getSignatures())
                {
                    if (sig.name.find("GWorld") != std::string::npos &&
                        (rawRVA = findOffsetInProcessMemory(
                            g_hTargetProcess, sig.pattern, sig.mask, "GWorld")))
                    {
                        break;
                    }
                }

                if (!rawRVA)
                {
                    Log(L"Failed to locate GWorld offset\r\n\r\n");
                }
                else
                {
                    HMODULE hMods[1];
                    DWORD   cbNeeded = 0;
                    if (EnumProcessModules(g_hTargetProcess, hMods, sizeof(hMods), &cbNeeded))
                    {
                        MODULEINFO mi{};
                        GetModuleInformation(g_hTargetProcess, hMods[0], &mi, sizeof(mi));

                        uintptr_t moduleBase = (uintptr_t)mi.lpBaseOfDll;
                        uintptr_t ptrAddress = moduleBase + (uintptr_t)rawRVA;

                        {
                            wchar_t dbg[64];
                            swprintf(dbg, 64,
                                L"Base Address: 0x%llX\r\n",
                                (unsigned long long)ptrAddress);
                            Log(dbg);
                        }

                        uint64_t realGWorld = 0;
                        SIZE_T  bytesRead = 0;
                        if (ReadProcessMemory(
                            g_hTargetProcess,
                            (LPCVOID)ptrAddress,
                            &realGWorld,
                            sizeof(realGWorld),
                            &bytesRead) &&
                            bytesRead == sizeof(realGWorld))
                        {
                            wchar_t buf[32];
                            swprintf(buf, 32, L"%llX", (unsigned long long)ptrAddress);
                            if (!g_isPointerScanning) {
                                SetWindowTextW(g_hEditBaseAddress, buf);
                            }
                            g_resolvedBaseAddress = ptrAddress;
                            SearchPositionalPointerPaths();
                            Log(L"\r\n");
                        }
                        else
                        {
                            Log(L"ReadProcessMemory for GWorld pointer failed\r\n\r\n");
                        }
                    }
                    else
                    {
                        Log(L"EnumProcessModules failed\r\n\r\n");
                    }
                }
            }
            else
            {
                g_unrealDetected = false;
            }
        }
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    FreeLibraryAndExitThread(g_hModule, (DWORD)msg.wParam);
    return (DWORD)msg.wParam;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_hModule = hModule;
        HANDLE hThread = CreateThread(nullptr, 0, MainThread, (LPVOID)hModule, 0, nullptr);
        if (hThread)
            CloseHandle(hThread);
    }
    break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

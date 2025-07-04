#pragma once

#include <cstdint>
#include <string>
#include <vector>

/*===========Enums & Typedefs==========*/

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

enum DataType {
    DATA_BYTE,
    DATA_2BYTE,
    DATA_4BYTE,
    DATA_8BYTE,
    DATA_FLOAT,
    DATA_DOUBLE
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

// In‑place edit
void SubclassEditControl(HWND hEdit);


class ScanResultPager;

// Prototypes for “Show, Select, and Inject/Attach helpers, 

void ShowEditAddressDialog(HWND hParent, int index);
void ShowAddAddressDialog(HWND hParent);

void SelectProcessDialog(HWND hParent);
void AttachToProcess(DWORD pid);
void InjectSelfIntoProcess(DWORD pid);

// Saved‑entry re‑resolution
void ResolvePendingSavedEntries();

// UI Helpers
void UpdateScanButtons(bool enabled);
void UpdateScanResultsListView();
void UpdateScanStatus();

// Scan core
bool PerformFirstScan(double searchVal, DataType dt, SearchMode searchMode);
bool PerformNextScan(double searchVal, DataType dt, SearchMode searchMode);
bool UndoScan();
void ResetScans();
bool GetSearchValueFromEdit(double& value);

// Hotkeys
void ShowHotkeysDialog(HWND hParent);

// Pause Process
static void PauseTargetProcess();
static void ResumeTargetProcess();

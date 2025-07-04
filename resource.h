#pragma once

#define IDI_ICON1                       101

// Next default values for new objects
// 
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        102
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1001
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif

//===========================================================================
// Definitions & Constants
//===========================================================================

// General Constants
#define IDT_UPDATE_TIMER           1
#define UPDATE_INTERVAL_MS         500

#ifndef BS_FLAT
#define BS_FLAT                    0x8000
#endif

// Menu Commands
#define ID_MENU_ATTACH             300
#define ID_MENU_PROCINFO           301
#define ID_MENU_THREAD             302
#define ID_MENU_SETTINGS           303
#define ID_MENU_HOTKEYS            304
#define ID_MENU_PAUSE_SCAN         306
#define ID_MENU_SUPPORT            305
#define IDM_COPY_MODULE_ADDR       40001

// Main Window Buttons
#define IDC_BTN_FIRSTSCAN          103
#define IDC_BTN_NEXTSCAN           104
#define IDC_BTN_UNDOSCAN           105
#define IDC_BTN_NEWSCAN            106
#define IDC_BTN_ADDADDRESS         210
#define IDC_BTN_SAVETABLE          211
#define IDC_BTN_LOADTABLE          212
#define IDC_BTN_SAVECT             213
#define IDC_BTN_EXIT               200

// Scan Results & Saved Lists
#define IDC_LIST_SCANRESULTS       107
#define IDC_LIST_SAVEDADDR         108
#define DEFAULT_DESC_WIDTH         126
#define DEFAULT_ADDR_WIDTH         100

// Scan Status & Progress
#define IDC_STATIC_SCANSTATUS      100
#define IDC_PROGRESS_BAR           110

// Value Input Controls
#define IDC_EDIT_VALUE             101
#define IDC_COMBO_VALUETYPE        102
#define IDC_COMBO_SEARCHMODE       109

// Address Addition Dialog
#define IDC_ADD_EDITADDRESS        501
#define IDC_ADD_COMBOTYPE          502
#define IDC_ADD_OK                 503
#define IDC_ADD_CANCEL             504

// Process List & Filtering
#define IDC_PROCESS_LIST           200
#define IDC_FILTER_TAB             300

// Pointer-Chain Frame
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

// Pointer-Chain Viewer
#define IDC_BTN_SAVE_PTRS          7001
#define IDT_PTRTABLE_UPDATE        8001
#define PTRTABLE_UPDATE_MS         500

// Offsets Group
#define IDC_GROUP_POSOFFSETS         620
#define IDC_LIST_OFFSETS             621
#define IDC_EDIT_OFFSETNEW           622
#define IDC_BTN_OFFSET_ADD           623
#define IDC_BTN_OFFSET_DEL           624
#define IDC_BTN_OFFSET_AUTO          625
#define IDC_OFFSET_CLEAR             630
#define IDC_CHECK_SCAN_SAVED_FILE    614

// Log Controls
#define IDC_EDIT_LOG               700
#define IDC_CLEAR_LOGS             701
#define IDC_LOG_COPY               702
#define IDC_LOG_SELECTALL          703
#define IDC_LOG_PIN                704

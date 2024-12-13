#pragma once
#include <cstdint>
#include <type_traits>
#include <bit>
#include <string>
#include "byteswap.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #define near
    #define far

    typedef char CHAR;
    typedef wchar_t WCHAR;
    typedef unsigned long DWORD;
    typedef int BOOL;
    typedef unsigned char BYTE;
    typedef unsigned short WORD;
    typedef float FLOAT;
    typedef FLOAT* PFLOAT;
    typedef BOOL near* PBOOL;
    typedef BOOL far* LPBOOL;
    typedef BYTE near* PBYTE;
    typedef BYTE far* LPBYTE;
    typedef int near* PINT;
    typedef int far* LPINT;
    typedef WORD near* PWORD;
    typedef WORD far* LPWORD;
    typedef long far* LPLONG;
    typedef DWORD near* PDWORD;
    typedef DWORD far* LPDWORD;
    typedef void far* LPVOID;
    typedef const void far* LPCVOID;
    typedef unsigned long ULONG;
    typedef ULONG* PULONG;
    typedef signed long LONG;
    typedef LONG* PLONG;
    typedef unsigned long long ULONGLONG;
    typedef ULONGLONG* PULONGLONG;
    typedef unsigned short USHORT;
    typedef USHORT* PUSHORT;
    typedef unsigned char UCHAR;
    typedef UCHAR* PUCHAR;
    typedef char* PSZ;
    typedef int INT;
    typedef unsigned int UINT;
    typedef unsigned int* PUINT;
#endif

// real win32 handles will never use the upper bits unless something goes really wrong
#define CHECK_GUEST_HANDLE(HANDLE) (((HANDLE) & 0x80000000) == 0x80000000)
#define GUEST_HANDLE(HANDLE) ((HANDLE) | 0x80000000)
#define HOST_HANDLE(HANDLE) ((HANDLE) & ~0x80000000)

// Return true to free the associated memory
typedef bool(*TypeDestructor_t)(void*);

template<typename T>
bool DestroyObject(void* obj)
{
    static_cast<T*>(obj)->~T();
    return true;
}

template<typename T>
struct be
{
    T value;

    be() : value(0)
    {
    }

    be(const T v)
    {
        set(v);
    }

    static T byteswap(T value)
    {
        if constexpr (std::is_same_v<T, double>)
        {
            const uint64_t swapped = ByteSwap(*reinterpret_cast<uint64_t*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else if constexpr (std::is_same_v<T, float>)
        {
            const uint32_t swapped = ByteSwap(*reinterpret_cast<uint32_t*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else if constexpr (std::is_enum_v<T>)
        {
            const std::underlying_type_t<T> swapped = ByteSwap(*reinterpret_cast<std::underlying_type_t<T>*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else
        {
            return ByteSwap(value);
        }
    }

    void set(const T v)
    {
        value = byteswap(v);
    }

    T get() const
    {
        return byteswap(value);
    }

    be& operator| (T value)
    {
        set(get() | value);
        return *this;
    }

    be& operator& (T value)
    {
        set(get() & value);
        return *this;
    }

    operator T() const
    {
        return get();
    }

    be& operator=(T v)
    {
        set(v);
        return *this;
    }
};

extern "C" void* MmGetHostAddress(uint32_t ptr);
template<typename T>
struct xpointer
{
    be<uint32_t> ptr;

    xpointer() : ptr(0)
    {
    }

    xpointer(T* ptr) : ptr((uint32_t)ptr)
    {
    }

    T* get() const
    {
        if (!ptr.value)
        {
            return nullptr;
        }

        return reinterpret_cast<T*>(MmGetHostAddress(ptr));
    }

    operator T* () const
    {
        return get();
    }

    T* operator->() const
    {
        return get();
    }
};

template<typename TGuest>
struct HostObject
{
    typedef TGuest guest_type;
};

typedef BYTE XBYTE;
typedef be<uint16_t> XWORD;
typedef be<uint32_t> XDWORD;
typedef be<uint64_t> XQWORD;

typedef XBYTE* XLPBYTE;
typedef XWORD* XLPWORD;
typedef XDWORD* XLPDWORD;
typedef XQWORD* XLPQWORD;

struct _XLIST_ENTRY;
typedef _XLIST_ENTRY XLIST_ENTRY;
typedef xpointer<XLIST_ENTRY> PXLIST_ENTRY;

typedef struct _IMAGE_CE_RUNTIME_FUNCTION
{
    DWORD BeginAddress;

    union 
    {
        DWORD Data;
        struct
        {
            DWORD PrologLength : 8;
            DWORD FunctionLength : 22;
            DWORD ThirtyTwoBit : 1;
            DWORD ExceptionFlag : 1;
        };
    };
} IMAGE_CE_RUNTIME_FUNCTION;

static_assert(sizeof(IMAGE_CE_RUNTIME_FUNCTION) == 8);

typedef struct _XLIST_ENTRY
{
    XDWORD Flink;
    XDWORD Blink;
} XLIST_ENTRY;

typedef struct _XDISPATCHER_HEADER
{
    union
    {
        struct
        {
            UCHAR Type;
            union
            {
                UCHAR Abandoned;
                UCHAR Absolute;
                UCHAR NpxIrql;
                UCHAR Signalling;
            };
            union
            {
                UCHAR Size;
                UCHAR Hand;
            };
            union
            {
                UCHAR Inserted;
                UCHAR DebugActive;
                UCHAR DpcActive;
            };
        };
        XDWORD Lock;
    };

    XDWORD SignalState;
    XLIST_ENTRY WaitListHead;
} XDISPATCHER_HEADER, * XPDISPATCHER_HEADER;

// These variables are never accessed in guest code, we can safely use them in little endian
typedef struct _XRTL_CRITICAL_SECTION
{
    XDISPATCHER_HEADER Header;
    long LockCount;
    int32_t RecursionCount;
    uint32_t OwningThread;
} XRTL_CRITICAL_SECTION;

typedef struct _XANSI_STRING {
    XWORD Length;
    XWORD MaximumLength;
    xpointer<char> Buffer;
} XANSI_STRING;

typedef struct _XOBJECT_ATTRIBUTES
{
    XDWORD RootDirectory;
    xpointer<XANSI_STRING> Name;
    xpointer<void> Attributes;
} XOBJECT_ATTRIBUTES;

typedef XDISPATCHER_HEADER XKEVENT;

typedef struct _XIO_STATUS_BLOCK
{
    union {
        XDWORD Status;
        XDWORD Pointer;
    };
    be<uint32_t> Information;
} XIO_STATUS_BLOCK;

typedef struct _XOVERLAPPED {
    XDWORD Internal;
    XDWORD InternalHigh;
    XDWORD Offset;
    XDWORD OffsetHigh;
    XDWORD hEvent;
} XOVERLAPPED;

// this name is so dumb
typedef struct _XXOVERLAPPED {
    union
    {
        struct
        {
            XDWORD Error;
            XDWORD Length;
        };

        struct
        {
            uint32_t InternalLow;
            uint32_t InternalHigh;
        };
    };
    uint32_t InternalContext;
    XDWORD hEvent;
    XDWORD pCompletionRoutine;
    XDWORD dwCompletionContext;
    XDWORD dwExtendedError;
} XXOVERLAPPED, *PXXOVERLAPPED;

static_assert(sizeof(_XXOVERLAPPED) == 0x1C);

// https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-memorystatus
typedef struct _XMEMORYSTATUS {
    XDWORD dwLength;
    XDWORD dwMemoryLoad;
    XDWORD dwTotalPhys;
    XDWORD dwAvailPhys;
    XDWORD dwTotalPageFile;
    XDWORD dwAvailPageFile;
    XDWORD dwTotalVirtual;
    XDWORD dwAvailVirtual;
} XMEMORYSTATUS, * XLPMEMORYSTATUS;

typedef struct _XVIDEO_MODE
{
    be<uint32_t> DisplayWidth;
    be<uint32_t> DisplayHeight;
    be<uint32_t> IsInterlaced;
    be<uint32_t> IsWidescreen;
    be<uint32_t> IsHighDefinition;
    be<uint32_t> RefreshRate;
    be<uint32_t> VideoStandard;
    be<uint32_t> Unknown4A;
    be<uint32_t> Unknown01;
    be<uint32_t> reserved[3];
} XVIDEO_MODE;

typedef struct _XKSEMAPHORE
{
    XDISPATCHER_HEADER Header;
    XDWORD Limit;
} XKSEMAPHORE;

typedef struct _XUSER_SIGNIN_INFO {
    be<ULONGLONG> xuid;
    XDWORD dwField08;
    XDWORD SigninState;
    XDWORD dwField10;
    XDWORD dwField14;
    CHAR Name[16];
} XUSER_SIGNIN_INFO;

typedef struct _XTIME_FIELDS
{
    XWORD Year;
    XWORD Month;
    XWORD Day;
    XWORD Hour;
    XWORD Minute;
    XWORD Second;
    XWORD Milliseconds;
    XWORD Weekday;
} XTIME_FIELDS, * PXTIME_FIELDS;

// Content types
#define XCONTENTTYPE_SAVEDATA 1
#define XCONTENTTYPE_DLC      2
#define XCONTENTTYPE_RESERVED 3

#define XCONTENT_NEW      1
#define XCONTENT_EXISTING 2

#define XCONTENT_MAX_DISPLAYNAME 128
#define XCONTENT_MAX_FILENAME    42
#define XCONTENTDEVICE_MAX_NAME  27

typedef struct _XCONTENT_DATA
{
    XDWORD DeviceID;
    XDWORD dwContentType;
    be<WCHAR> szDisplayName[XCONTENT_MAX_DISPLAYNAME];
    CHAR szFileName[XCONTENT_MAX_FILENAME];
} XCONTENT_DATA, * PXCONTENT_DATA;

typedef struct _XHOSTCONTENT_DATA : _XCONTENT_DATA
{
    // This is a host exclusive type so we don't care what goes on
    std::string szRoot{};
} XHOSTCONTENT_DATA, *PXHOSTCONTENT_DATA;


#define XCONTENTDEVICETYPE_HDD 1
#define XCONTENTDEVICETYPE_MU 2

typedef struct _XDEVICE_DATA
{
    XDWORD DeviceID;
    XDWORD DeviceType;
    XQWORD ulDeviceBytes;
    XQWORD ulDeviceFreeBytes;
    be<WCHAR> wszName[XCONTENTDEVICE_MAX_NAME];
} XDEVICE_DATA, *PXDEVICE_DATA;

// Direct reflection of XInput structures

#define XAMINPUT_DEVTYPE_GAMEPAD          0x01
#define XAMINPUT_DEVSUBTYPE_GAMEPAD       0x01

#define XAMINPUT_GAMEPAD_DPAD_UP          0x0001
#define XAMINPUT_GAMEPAD_DPAD_DOWN        0x0002
#define XAMINPUT_GAMEPAD_DPAD_LEFT        0x0004
#define XAMINPUT_GAMEPAD_DPAD_RIGHT       0x0008
#define XAMINPUT_GAMEPAD_START            0x0010
#define XAMINPUT_GAMEPAD_BACK             0x0020
#define XAMINPUT_GAMEPAD_LEFT_THUMB       0x0040
#define XAMINPUT_GAMEPAD_RIGHT_THUMB      0x0080
#define XAMINPUT_GAMEPAD_LEFT_SHOULDER    0x0100
#define XAMINPUT_GAMEPAD_RIGHT_SHOULDER   0x0200
#define XAMINPUT_GAMEPAD_A                0x1000
#define XAMINPUT_GAMEPAD_B                0x2000
#define XAMINPUT_GAMEPAD_X                0x4000
#define XAMINPUT_GAMEPAD_Y                0x8000

typedef struct _XAMINPUT_GAMEPAD
{
    WORD                                wButtons;
    BYTE                                bLeftTrigger;
    BYTE                                bRightTrigger;
    SHORT                               sThumbLX;
    SHORT                               sThumbLY;
    SHORT                               sThumbRX;
    SHORT                               sThumbRY;
} XAMINPUT_GAMEPAD, *PXAMINPUT_GAMEPAD;

typedef struct _XAMINPUT_VIBRATION
{
    WORD                                wLeftMotorSpeed;
    WORD                                wRightMotorSpeed;
} XAMINPUT_VIBRATION, * PXAMINPUT_VIBRATION;

typedef struct _XAMINPUT_CAPABILITIES
{
    BYTE                                Type;
    BYTE                                SubType;
    WORD                                Flags;
    XAMINPUT_GAMEPAD                    Gamepad;
    XAMINPUT_VIBRATION                  Vibration;
} XAMINPUT_CAPABILITIES, * PXAMINPUT_CAPABILITIES;

typedef struct _XAMINPUT_STATE
{
    DWORD                               dwPacketNumber;
    XAMINPUT_GAMEPAD                    Gamepad;
} XAMINPUT_STATE, * PXAMINPUT_STATE;

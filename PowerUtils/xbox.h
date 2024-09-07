#pragma once
#include <cstdint>
#include <type_traits>
#include <bit>

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
            const uint64_t swapped = std::byteswap(*reinterpret_cast<uint64_t*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else if constexpr (std::is_same_v<T, float>)
        {
            const uint32_t swapped = std::byteswap(*reinterpret_cast<uint32_t*>(&value));
            return *reinterpret_cast<const T*>(&swapped);
        }
        else
        {
            return std::byteswap(value);
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

template<typename T>
struct xpointer
{
    be<uint32_t> ptr;

    xpointer(T* ptr) : ptr(ptr)
    {

    }

    T* get() const
    {
        if (!ptr.value)
        {
            return nullptr;
        }

        return static_cast<T*>(ptr);
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
#pragma once
#include<Ntifs.h>
#include<ntddk.h>
#include <wsk.h>
#include<intrin.h>
#include <ntstrsafe.h>
#include <WinDef.h>

#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p) ExFreePool(_p)
typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef FLOAT               *PFLOAT;
typedef DWORD *LPDWORD;
typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int        *PUINT;
typedef struct _OVERLAPPED {
	ULONG_PTR Internal;
	ULONG_PTR InternalHigh;
	union {
		struct {
			DWORD Offset;
			DWORD OffsetHigh;
		} DUMMYSTRUCTNAME;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	HANDLE  hEvent;
} OVERLAPPED, *LPOVERLAPPED;

KIRQL WPOFFx64();
void WPONx64(KIRQL irql);
VOID OutPut(const char* fmt, ...);
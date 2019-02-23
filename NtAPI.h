#pragma once
#include "NtHread.h"
#include "Struct.h"
#ifdef __cplusplus
extern "C"
{
#endif
	UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
	

	NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation
	(
		IN ULONG	SystemInformationClass,
		OUT PVOID	SystemInformation,
		IN ULONG	Length,
		OUT PULONG	ReturnLength
	);

	NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(
		_In_ PEPROCESS Process
	);

#ifdef __cplusplus
}
#endif

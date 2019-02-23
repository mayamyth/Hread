#include "FastFunction.h"



ULONG64 FastFunction::GetSystemModuleBase(char* lpModuleName)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return 0;
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			kfree(pBuffer);
			return 0;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	ModuleCount = pSystemModuleInformation->ModuleCount;

	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].ImageBase) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].PathLength;
			if (_stricmp(pDrvName, lpModuleName) == 0)
				return (ULONG64)pSystemModuleInformation->Module[i].ImageBase;
		}
	}
	kfree(pBuffer);
	return 0;
}

VOID FastFunction::GetSystemModuleBase(char * lpModuleName, ULONG64 * ByRefBase, ULONG * ByRefSize)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return;
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			kfree(pBuffer);
			return;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	ModuleCount = pSystemModuleInformation->ModuleCount;
	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].ImageBase) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].PathLength;
			if (_stricmp(pDrvName, lpModuleName) == 0)
			{
				*ByRefBase = (ULONG64)pSystemModuleInformation->Module[i].ImageBase;
				*ByRefSize = pSystemModuleInformation->Module[i].ImageSize;
				goto exit_sub;
			}
		}
	}
exit_sub:
	kfree(pBuffer);
}

NTSTATUS FastFunction::HideDriver(char * pDrvName,PDRIVER_OBJECT pPDriverObj)
{
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pPDriverObj->DriverSection;
	PKLDR_DATA_TABLE_ENTRY firstentry;
	ULONG64 pDrvBase = 0;
	KIRQL OldIrql;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	firstentry = entry;
	pDrvBase = GetSystemModuleBase(pDrvName);
	DbgPrintEx(77, 0, "驱动基址 = %p.\n", pDrvBase);
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
	
			if (entry->DllBase == pDrvBase)
			{
				DbgPrintEx(77, 0, "找到开始清空.\n");
				OldIrql = KeRaiseIrqlToDpcLevel();
				((LIST_ENTRY64*)(entry->InLoadOrderLinks.Flink))->Blink = entry->InLoadOrderLinks.Blink;
				((LIST_ENTRY64*)(entry->InLoadOrderLinks.Blink))->Flink = entry->InLoadOrderLinks.Flink;
				entry->InLoadOrderLinks.Flink = 0;
				entry->InLoadOrderLinks.Blink = 0;
				KeLowerIrql(OldIrql);
				Status = STATUS_SUCCESS;
				break;
			}

		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	return Status;
}

PVOID FastFunction::RvaToVaHades(PVOID pModuleBase, ULONG Rva)
{
	if (Rva == 0)
	{
		return NULL;
	}

	return (PVOID)((PUCHAR)pModuleBase + Rva);
}

PVOID FastFunction::GetModuleExport(PVOID pModuleBase, PCHAR pExportName)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	PIMAGE_NT_HEADERS32 pNtHeaders32 = (PIMAGE_NT_HEADERS32)RvaToVaHades(pModuleBase, pDosHeader->e_lfanew);
	PIMAGE_NT_HEADERS64 pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders32;
	if (pNtHeaders64 == NULL || pNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	if (pNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pDataDirectory = &pNtHeaders64->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (pNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		pDataDirectory = &pNtHeaders32->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RvaToVaHades(pModuleBase, pDataDirectory->VirtualAddress);
	ULONG ExportDirectorySize = pDataDirectory->Size;
	if (pExportDirectory == NULL)
	{
		return NULL;
	}
	PULONG NameTable = (PULONG)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfNames);
	PULONG AddressTable = (PULONG)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfFunctions);
	PUSHORT OrdinalsTable = (PUSHORT)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfNameOrdinals);
	if (NameTable == NULL || AddressTable == NULL || OrdinalsTable == NULL)
	{
		return NULL;
	}
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		PCHAR pCurrentName = (PCHAR)RvaToVaHades(pModuleBase, NameTable[i]);

		if (pCurrentName != NULL && strncmp(pExportName, pCurrentName, 256) == 0)
		{
			USHORT CurrentOrd = OrdinalsTable[i];

			if (CurrentOrd < pExportDirectory->NumberOfFunctions)
			{
				PVOID pExportAddress = RvaToVaHades(pModuleBase, AddressTable[CurrentOrd]);

				if ((ULONG_PTR)pExportAddress >= (ULONG_PTR)pExportDirectory &&
					(ULONG_PTR)pExportAddress <= (ULONG_PTR)pExportDirectory + ExportDirectorySize)
				{
					return NULL;
				}
				return pExportAddress;
			}

			return NULL;
		}
	}

	return NULL;
}

PVOID FastFunction::GetModuleBaseWow64(PEPROCESS pEProcess, PWCHAR pModuleName)
{
	NTSTATUS nStatus;
	PPEB32 pPeb = NULL;
	UNICODE_STRING usModuleName = { 0 };
	RtlInitUnicodeString(&usModuleName, pModuleName);
	pPeb = (PPEB32)PsGetProcessWow64Process(pEProcess);
	if (pPeb == NULL || pPeb->Ldr == 0) {
		return NULL;
	}
	for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
		pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList;
		pListEntry = (PLIST_ENTRY32)pListEntry->Flink) 
	{
		PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		if (LdrEntry->BaseDllName.Buffer == NULL)
		{
			continue;
		}

		UNICODE_STRING usCurrentName = { 0 };
		RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);
		if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE))
		{
			return (PVOID)LdrEntry->DllBase;
			
		}
	}

	return NULL;

}

PEPROCESS FastFunction::GetProcessPeprocess(int Pid)
{
	PEPROCESS Pe = NULL;
	PsLookupProcessByProcessId((HANDLE)Pid, &Pe);
	return Pe;
}

PVOID FastFunction::GetFunctionFromModule(PEPROCESS pEProcess, PWCHAR DllName, PCHAR FunctionName,BOOLEAN IsAttach)
{
	KAPC_STATE KAPC = { 0 };
	PVOID BaseAddr = NULL;
	if (IsAttach) {
		KeStackAttachProcess(pEProcess, &KAPC);
	}
	PVOID pNtdllBase = GetModuleBaseWow64(pEProcess, DllName);
	if (pNtdllBase == NULL) {
		goto $EXIT;
	}
	BaseAddr = GetModuleExport(pNtdllBase, FunctionName);
$EXIT:
	if (IsAttach) {
		KeUnstackDetachProcess(&KAPC);
	}
	return BaseAddr;
}

char* FastFunction::GetProcessNamebyHandle(HANDLE handle)
{
	PEPROCESS Process;
	NTSTATUS status;
	char *nameptr = NULL;
	status = ObReferenceObjectByHandle(handle, 0, NULL, KernelMode, (PVOID *)&Process, NULL);
	if (!NT_SUCCESS(status))
	{
		return NULL;
	}
	return (char *)PsGetProcessImageFileName(Process);
}

NTSTATUS FastFunction::ApcpQuerySystemProcessInformation(PSYSTEM_PROCESS_INFO * SystemInfo)
{
	PSYSTEM_PROCESS_INFO pBuffer = NULL;
	ULONG BufferSize = 0;
	ULONG RequiredSize = 0;

	NTSTATUS status = STATUS_SUCCESS;
	while ((status = ZwQuerySystemInformation(
		SystemProcessInformation,
		pBuffer,
		BufferSize,
		&RequiredSize//retn Length
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		BufferSize = RequiredSize;
		pBuffer = (PSYSTEM_PROCESS_INFO)ExAllocatePool(PagedPool, BufferSize);
	}

	if (!NT_SUCCESS(status))
	{
		if (pBuffer != NULL)
		{
			ExFreePool(pBuffer);
		}

		return status;
	}
	//retn pSystemProcessInfo
	*SystemInfo = pBuffer;
	return status;
}

NTSTATUS FastFunction::GetProcessThreadInfo(IN ULONG Pid, OUT ULONG *ThreadNuber, OUT PULONG64 Tid, OUT PULONG64 StartAddr)
{
	PEPROCESS pEProcess;
	PSYSTEM_PROCESS_INFO OriginalSystemProcessInfo = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	if (MmIsAddressValid(ThreadNuber) == 0)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	if (MmIsAddressValid(StartAddr) == 0)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	if (MmIsAddressValid(Tid) == 0)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}

	status = ApcpQuerySystemProcessInformation(&OriginalSystemProcessInfo);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEProcess);
		return status;
	}


	PSYSTEM_PROCESS_INFO SystemProcessInfo = OriginalSystemProcessInfo;
	status = STATUS_NOT_FOUND;
	do
	{
		if (SystemProcessInfo->UniqueProcessId == PsGetProcessId(pEProcess))
		{
			status = STATUS_SUCCESS;
			break;
		}

		SystemProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
	} while (SystemProcessInfo->NextEntryOffset != 0);

	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEProcess);
		ExFreePool(OriginalSystemProcessInfo);
		return status;
	}
	*ThreadNuber = SystemProcessInfo->NumberOfThreads;

	for (ULONG Index = 0; Index < SystemProcessInfo->NumberOfThreads; ++Index)
	{
		HANDLE UniqueThreadId = SystemProcessInfo->Threads[Index].ClientId.UniqueThread;
		Tid[Index] = (ULONG64)UniqueThreadId;
		StartAddr[Index] = (ULONG64)SystemProcessInfo->Threads[Index].StartAddress;
	}

	ObDereferenceObject(pEProcess);
	return status;
}



HANDLE FastFunction::OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
	OBJECT_ATTRIBUTES      ObjectAttributes = { 0, };
	CLIENT_ID              ClientId = { 0, };
	HANDLE                 hThread = NULL;
	NTSTATUS               Status;
	SSDT _SSDT;

	_SSDT.SSDT_Init();

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	if (bInheritHandle) {
		ObjectAttributes.Attributes = OBJ_INHERIT;
	}

	ClientId.UniqueProcess = NULL;
	ClientId.UniqueThread = (HANDLE)dwThreadId;
	NtOpenThread = (NTSTATUS(__cdecl *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))_SSDT.GetSSDTFuncCurAddrByIndex(SSDT_OPEN_THREAD);
	if (NtOpenThread == NULL) {
		return NtOpenThread;
	}

	Status = NtOpenThread(&hThread,
		dwDesiredAccess,
		&ObjectAttributes,
		&ClientId);
	OutPut("<-->错误代码 = %X\n", Status);
	_SSDT.Un_SSDTClass();
	return hThread;
}

NTSTATUS FastFunction::SuspendThread(HANDLE ThreadHandle)
{
	SSDT                   _SSDT;
	NTSTATUS               Status;
	_SSDT.SSDT_Init();
	NtSuspendThread = (NTSTATUS(__cdecl *)(HANDLE, PULONG))_SSDT.GetSSDTFuncCurAddrByIndex(SSDT_NTSUSPENDTHRED);
	Status = NtSuspendThread(ThreadHandle, NULL);
	OutPut("<-->错误代码 = %X\n", Status);
	_SSDT.Un_SSDTClass();
	return Status;
}

NTSTATUS FastFunction::ResumeThread(HANDLE hThread)
{
	SSDT                   _SSDT;
	NTSTATUS               Status;
	_SSDT.SSDT_Init();
	NtResumeThread = (NTSTATUS(__cdecl *)(HANDLE, PULONG))_SSDT.GetSSDTFuncCurAddrByIndex(SSDT_RESUMETHREAD);
	Status = NtResumeThread(hThread, NULL);
	OutPut("<-->错误代码 = %X\n", Status);
	_SSDT.Un_SSDTClass();
	return Status;
}

NTSTATUS FastFunction::GetDriverThread(char * DriverName, OUT ULONG * ThreadNuber, OUT PULONG64 Tid)
{
	ULONG64				DriverBaseAddr = 0;
	ULONG    			DriverSize = 0;
	ULONG				Number = 0;
	ULONG				Number1 = 0;
	ULONG64              __Tid[THREAD_MAX_NUMBER] = { 0 };
	ULONG64              __ThreadStartAddr[THREAD_MAX_NUMBER] = { 0 };
	NTSTATUS            Status = STATUS_UNSUCCESSFUL;
	PETHREAD			Et = NULL;
	ULONG               Count = 0;
	GetSystemModuleBase(DriverName, &DriverBaseAddr, &DriverSize);
	if (DriverBaseAddr == 0 || DriverSize == 0) {
		return Status;
	}
	Status = GetProcessThreadInfo(4, &Number, __Tid, __ThreadStartAddr);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	for (ULONG i = 0; i < Number; i++) 
	{
		if (__ThreadStartAddr[i] >= DriverBaseAddr)
		{
			if (__ThreadStartAddr[i] <= DriverBaseAddr + DriverSize)
			{
				Tid[Count] = __Tid[i];
				Count++;
			}
		}
	}
	*ThreadNuber = Count;
	return STATUS_SUCCESS;
}






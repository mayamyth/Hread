#include "HOOK.h"




VOID HOOK::Hook_Init()
{
	m_SSDT.SSDT_Init();
	LDE_init();
}

PVOID HOOK::HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID * Original_ApiAddress, OUT ULONG * PatchSize)
{
	KIRQL irql;
	UINT64 tmpv;
	PVOID head_n_byte, ori_func;
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	UCHAR jmp_code_orifunc[] = "\xFF\x25\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	*PatchSize = GetPatchSize((PUCHAR)ApiAddress);
	head_n_byte = kmalloc(*PatchSize);
	irql = WPOFFx64();
	memcpy(head_n_byte, ApiAddress, *PatchSize);
	WPONx64(irql);
	ori_func = kmalloc(*PatchSize + 14);
	RtlFillMemory(ori_func, *PatchSize + 14, 0x90);
	tmpv = (ULONG64)ApiAddress + *PatchSize;
	memcpy(jmp_code_orifunc + 6, &tmpv, 8);
	memcpy((PUCHAR)ori_func, head_n_byte, *PatchSize);
	memcpy((PUCHAR)ori_func + *PatchSize, jmp_code_orifunc, 14);
	*Original_ApiAddress = ori_func;
	tmpv = (UINT64)Proxy_ApiAddress;
	memcpy(jmp_code + 6, &tmpv, 8);
	irql = WPOFFx64();
	RtlFillMemory(ApiAddress, *PatchSize, 0x90);
	memcpy(ApiAddress, jmp_code, 14);
	WPONx64(irql);
	return head_n_byte;;
}

VOID HOOK::UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize)
{
	KIRQL irql;
	irql = WPOFFx64();
	memcpy(ApiAddress, OriCode, PatchSize);
	WPONx64(irql);
}

VOID HOOK::HookSSSDT(ULONG FunctionId, ULONG64 ProxyFunctionAddress, CHAR ParamCount)
{
	ULONG64 FreeSpace = 0, OriFunctionAddress = 0;
	LONG lng = 0;
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00";
	ULONG64 Win32kBase = 0;
	ULONG Win32kSize = 0;
	FastFunction::GetSystemModuleBase("win32k.sys", &Win32kBase, &Win32kSize);
	if (Win32kBase == 0 || Win32kSize == 0) {
		return;
	}
	FreeSpace = FindFreeSpace(Win32kBase, Win32kSize);
	if (FreeSpace == 0) {
		return;
	}
	SafeMemcpy((PVOID)FreeSpace, &ProxyFunctionAddress, 8);
	OriFunctionAddress = m_SSDT.GetSSDTFuncCurAddrByIndex(FunctionId);
	lng = (LONG)(FreeSpace - (OriFunctionAddress - 6) - 6);
	memcpy(&jmp_code[2], &lng, 4);
	SafeMemcpy((PVOID)(OriFunctionAddress - 6), jmp_code, 6);
	ModifySSSDT(FunctionId, OriFunctionAddress - 6, ParamCount);
}

VOID HOOK::UnHookSSSDT(ULONG FunctionId, ULONG64 OriFunctionAddress, CHAR ParamCount)
{
	ModifySSSDT(FunctionId, (ULONG64)OriFunctionAddress, ParamCount);
}

ULONGLONG HOOK::GetSSDTFuncCurAddr(ULONG id)
{
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)m_SSDT.KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	dwtmp = dwtmp >> 4;
	return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}
VOID HOOK::HookSSDT(IN int SSDTID, IN ULONGLONG Proxy_ApiAddress,PULONG OldTpVal, PVOID *OldFun)
{
	if (m_SSDT.KeServiceDescriptorTable == NULL)
	{
		return;
	}
	if (SSDTID < 0)
	{
		return;
	}

	KIRQL irql;
	ULONGLONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;

	FuckKeBugCheckEx(Proxy_ApiAddress);
	ServiceTableBase = (PULONG)m_SSDT.KeServiceDescriptorTable->ServiceTableBase;
	if (ServiceTableBase == NULL)
	{
		return;
	}

	if (MmIsAddressValid(ServiceTableBase) == FALSE)
	{
		return;
	}

	if (MmIsAddressValid((PVOID)GetSSDTFuncCurAddr(SSDTID)))
	{
		*OldTpVal = ServiceTableBase[SSDTID];
		*OldFun = (PVOID)GetSSDTFuncCurAddr(SSDTID);
		irql = WPOFFx64();
		ServiceTableBase[SSDTID] = GetOffsetAddress((ULONGLONG)KeBugCheckEx);
		WPONx64(irql);

	}
	else 
	{
		return;
	}

	
}



VOID HOOK::UnHookSSDT(IN int SSDTID, IN ULONG OldTpVal)
{
	KIRQL irql;
	ULONGLONG dwtemp = 0;
	PULONG ServiceTableBase = 0;

	ServiceTableBase = (PULONG)m_SSDT.KeServiceDescriptorTable->ServiceTableBase;
	irql = WPOFFx64();
	ServiceTableBase[SSDTID] = OldTpVal;
	WPONx64(irql);
}

ULONG HOOK::GetOffsetAddress(ULONGLONG FuncAddr)
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)m_SSDT.KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
	return dwtmp << 4;
}

VOID HOOK::FuckKeBugCheckEx(ULONGLONG Proxy_ApiAddress)
{
	KIRQL irql;
	ULONGLONG myfun;
	UCHAR jmp_code[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0";
	myfun = Proxy_ApiAddress;
	memcpy(jmp_code + 2, &myfun, 8);
	irql = WPOFFx64();
	memset(KeBugCheckEx, 0x90, 15);
	memcpy(KeBugCheckEx, jmp_code, 12);
	WPONx64(irql);
}


VOID HOOK::Un_HookClass()
{
	if (!m_LDE) {
		ExFreePool(m_LDE);
		m_LDE = NULL;
	}
	m_SSDT.Un_SSDTClass();
}

ULONG64 HOOK::FindFreeSpace(ULONG64 StartAddress, ULONG64 Length)
{
	ULONG64 i = 0, qw = 0;
	for (i = StartAddress; i < StartAddress + Length; i++)
	{
		if (*(PUCHAR)i == 0xC3)
		{
			RtlMoveMemory(&qw, (PVOID)(i + 1), 8);
			if (qw == 0x9090909090909090)
			{
				return i + 1;
			}
		}
	}
	return 0;
}

VOID HOOK::LDE_init()
{
	m_LDE = (LDE_DISASM)ExAllocatePool(NonPagedPool, 12800);
	memcpy(m_LDE, szShellCode, 12800);
}

ULONG HOOK::GetPatchSize(PUCHAR Address)
{
	ULONG LenCount = 0, Len = 0;
	while (LenCount <= 14)
	{
		Len = m_LDE(Address, 64);
		Address = Address + Len;
		LenCount = LenCount + Len;
	}
	return LenCount;
}

void HOOK::SafeMemcpy(PVOID dst, PVOID src, DWORD length)
{

	KIRQL irql;
	irql = WPOFFx64();
	memcpy(dst, src, length);
	WPONx64(irql);

}

VOID HOOK::ModifySSSDT(ULONG64 Index, ULONG64 Address, CHAR ParamCount)
{
	CHAR b = 0, bits[4] = { 0 };
	LONG i;

	ULONGLONG				W32pServiceTable = 0, qwTemp = 0;
	LONG 					dwTemp = 0;
	PSYSTEM_SERVICE_TABLE	pWin32k;
	KIRQL					irql;
	pWin32k = (PSYSTEM_SERVICE_TABLE)((ULONG64)m_SSDT.KeServiceDescriptorTable + sizeof(SYSTEM_SERVICE_TABLE));	//4*8
	W32pServiceTable = (ULONGLONG)(pWin32k->ServiceTableBase);
	qwTemp = W32pServiceTable + 4 * (Index - 0x1000);
	dwTemp = (LONG)(Address - W32pServiceTable);
	dwTemp = dwTemp << 4;
	if (ParamCount > 4)
		ParamCount = ParamCount - 4;
	else
		ParamCount = 0;
	memcpy(&b, &dwTemp, 1);
	for (i = 0; i < 4; i++)
	{
		bits[i] = GETBIT(ParamCount, i);
		if (bits[i])
			SETBIT(b, i);
		else
			CLRBIT(b, i);
	}
	memcpy(&dwTemp, &b, 1);

	irql = WPOFFx64();
	*(PLONG)qwTemp = dwTemp;
	WPONx64(irql);
}




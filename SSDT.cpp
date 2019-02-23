#include "SSDT.h"

VOID SSDT::SSDT_Init()
{
	GetKeServiceDescriptorTableAddrX64();
}

ULONG64 SSDT::GetSSDTFuncCurAddrByIndex(ULONG index)
{
	
	LONG dwtmp = 0;
	ULONGLONG addr = 0;
	PULONG ServiceTableBase = NULL;
	if (KeServiceDescriptorTable != NULL) {
		ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
		dwtmp = ServiceTableBase[index];
		dwtmp = dwtmp >> 4;
		addr = ((LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase);//&0xFFFFFFF0;
	}
	return addr;
}

VOID SSDT::Un_SSDTClass()
{
	this->KeServiceDescriptorTable = nullptr;
}

void SSDT::GetKeServiceDescriptorTableAddrX64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONGLONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *(i);
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)addr;
}

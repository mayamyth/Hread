#pragma once
#include "NtAPI.h"
#include "Struct.h"
class SSDT
{
public:
	VOID SSDT_Init();
	ULONG64 GetSSDTFuncCurAddrByIndex(ULONG index);
	VOID Un_SSDTClass();
public:
	PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable = nullptr;
private:
	void GetKeServiceDescriptorTableAddrX64();
	
};



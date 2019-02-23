#pragma once
#include "NtHread.h"
#include "Struct.h"
#include "NtAPI.h"
#define GAME_NAME "r5apex.exe"
#define GAME_NAME1 "r5apex.exe"
class R3_ReadProcess
{
public:
	NTSTATUS R3_ReadProcess_Start(PDRIVER_OBJECT pPDriverObj);
	
	VOID UnLoad_R3_ReadProcess();
private:
      NTSTATUS Start_ProcessObProcess();
	  NTSTATUS Start_ThradObProcess();
private:
	static OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
	static OB_PREOP_CALLBACK_STATUS preCall2(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
private:
	PVOID m_ProcessHandle = NULL;
	PVOID m_ThreadHandle = NULL;
};


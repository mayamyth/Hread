#include "R3_ReadProcess.h"

NTSTATUS R3_ReadProcess:: R3_ReadProcess_Start(PDRIVER_OBJECT pPDriverObj)
{
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)pPDriverObj->DriverSection;
	ldr->Flags |= 0x20;
	if (!NT_SUCCESS(Start_ProcessObProcess())) {
		return STATUS_UNSUCCESSFUL;
	}
	return Start_ThradObProcess();
}

NTSTATUS R3_ReadProcess::Start_ProcessObProcess()
{
	NTSTATUS status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"25444");
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)preCall;
	obReg.OperationRegistration = &opReg;
	status = ObRegisterCallbacks(&obReg, &m_ProcessHandle);
	return status;
}

NTSTATUS R3_ReadProcess::Start_ThradObProcess()
{
	NTSTATUS status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"25444");
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsThreadType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)preCall2;
	obReg.OperationRegistration = &opReg;
	status = ObRegisterCallbacks(&obReg, &m_ThreadHandle);
	return status;
}

VOID R3_ReadProcess::UnLoad_R3_ReadProcess()
{
	if (m_ProcessHandle) {
		ObUnRegisterCallbacks(m_ProcessHandle);
		m_ProcessHandle = NULL;
	}

	if (m_ThreadHandle) {
		ObUnRegisterCallbacks(m_ThreadHandle);
		m_ThreadHandle = NULL;
	}
}

OB_PREOP_CALLBACK_STATUS R3_ReadProcess::preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (strcmp((char *)PsGetProcessImageFileName(IoGetCurrentProcess()),GAME_NAME) == 0 || strcmp((char *)PsGetProcessImageFileName(IoGetCurrentProcess()), GAME_NAME1) == 0)
	{
		return OB_PREOP_SUCCESS;
	}
	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
	pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS R3_ReadProcess::preCall2(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	if (strcmp((char *)PsGetProcessImageFileName(IoGetCurrentProcess()), GAME_NAME) == 0 || strcmp((char *)PsGetProcessImageFileName(IoGetCurrentProcess()), GAME_NAME1) == 0)
	{
		return OB_PREOP_SUCCESS;
	}
	pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
	pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
	return OB_PREOP_SUCCESS;
}

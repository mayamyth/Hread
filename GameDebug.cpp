#include "GameDebug.h"

NTSTATUS GameDebug::Start_GanmeDebug()
{
	g_GameDebug = this;
	m_Hook.Hook_Init();
	NTSTATUS Status = R3_PassTp_Hook();
	PassTp_DebugPort_Set_0();
	return Status;
}

VOID GameDebug::Un_GanmeDebug()
{
	PsRemoveCreateThreadNotifyRoutine(ThreadCallback);
	if (m_IsHook) {
		m_Hook.UnHookSSDT(361, m_OldTpVal);
	}
}

NTSTATUS GameDebug::R3_PassTp_Hook()
{

   return PsSetCreateThreadNotifyRoutine(ThreadCallback);
}


VOID GameDebug::PassTp_DebugPort_Set_0()
{
	HOOK_NtRemoveProcessDebug();
}

VOID GameDebug::HOOK_NtRemoveProcessDebug()
{
	m_Hook.HookSSDT(361, (ULONGLONG)Fake_NtRemoveProcessDebug,&m_OldTpVal, (PVOID *)&NtRemoveProcessDebug);
	m_IsHook = TRUE;
}

NTSTATUS GameDebug::Fake_NtRemoveProcessDebug(IN HANDLE ProcessHandle, IN HANDLE DebugHandle)
{
	
	if (_stricmp((char *)PsGetProcessImageFileName(IoGetCurrentProcess()), "System") ==0 &&
		_stricmp(FastFunction::GetProcessNamebyHandle(ProcessHandle), "dnf.exe") == 0) 
	{

		return STATUS_SUCCESS;
	}
	return NtRemoveProcessDebug(ProcessHandle, DebugHandle);
}

VOID GameDebug::ThreadCallback(IN HANDLE ProcessId, IN HANDLE ThreadId, IN BOOLEAN Create)
{
  
}


#pragma once
#include "NtAPI.h"
#include "HOOK.h"
class GameDebug;
static GameDebug *g_GameDebug;
static NTSTATUS(__fastcall *NtRemoveProcessDebug)(IN HANDLE ProcessHandle, IN HANDLE DebugHandle) = NULL;
class GameDebug
{
public:
	NTSTATUS Start_GanmeDebug();
	VOID Un_GanmeDebug();
private:
	NTSTATUS R3_PassTp_Hook();
private:
	VOID PassTp_DebugPort_Set_0();
	VOID HOOK_NtRemoveProcessDebug();
    
private:
	static NTSTATUS Fake_NtRemoveProcessDebug(IN HANDLE ProcessHandle, IN HANDLE DebugHandle);

private:
	static VOID ThreadCallback(IN HANDLE  ProcessId, IN HANDLE   ThreadId, IN BOOLEAN Create);
private:
	HOOK m_Hook;
	BOOLEAN m_IsHook = FALSE;
	ULONG m_OldTpVal = 0;

};


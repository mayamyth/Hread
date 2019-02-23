#include "NtHread.h"

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}




VOID OutPut(const char* fmt, ...)
{
UNREFERENCED_PARAMETER(fmt);
	va_list ap;
	va_start(ap, fmt);
#ifdef DBG
	vKdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ap));
#else
	vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ap);
#endif 
	va_end(ap);
}

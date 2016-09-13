// https://github.com/nemesisqp/al-khaser/blob/master/DebuggerDetection.cpp
// http://www.symantec.com/connect/articles/windows-anti-debug-reference

/******************************************************************************
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 *                                                                            *
 ******************************************************************************/

#include <Windows.h>
#include <winternl.h>

#include "anti.h"
#include "peb.h"

#ifdef ANTI_VIRTUAL_MACHINE

BOOL CheckForVMArtefacts(VOID) {

}
#endif

#ifdef ANTI_DEBUGGING
/*
	PEB->BeingDebugged method (IsDebuggerPresent)
	PEB->BeingDebugged will have value of 1 if
	there is a debugger on the process

	Note: PEB structure may change in the future
	making it unreliable
*/
static BOOL MyIsDebuggerPresent(VOID) {
	BOOL bRet = FALSE;

	/*
		PPEB peb = (PPEB)__readfsdword(0x30);
		return peb->BeingDebugged;
	*/
	__asm {
		mov eax, fs:[0x30]
		movzx eax, [eax + 0x2]
		mov bRet, eax
	}

	return bRet;
}

/*
	NtGlobalFlag method
	If process is created by debugger, PEB +
	offset 0x68 (32-bit) will have the value 0x70
*/
static BOOL CheckNtGlobalFlag(VOID) {
	DWORD dwFlag = 0;

	__asm {
		mov eax, fs:[0x30]
		mov eax, [eax + 0x68]
		mov dwFlag, eax
	}

	if (dwFlag & 0x70)
		return TRUE;

	return FALSE;
}

// check this
static BOOL CheckHeapFlags(VOID) {
	BOOL bRet = FALSE;
	__asm {
		mov eax, fs:[0x30]
		mov eax, [eax + 0x18]
		mov eax, [eax + 0x44]
		mov bRet, eax;			// 1 (TRUE) if there is a debugger else 0 (FALSE)
	}

	return bRet;
}

/*
	NtQueryInformationProcess called with
	ProcessDebugPort will set ProcessInformation
	to -1 if the process is being debugged

	Note: NtQueryInformationProcess may be
	unreliable as it is susceptible to change
*/
static BOOL MyNtQueryInformationProcess(VOID) {
	/*
		Dynamically load the function since it's
		only available with this method (AFAIK)
	*/
	typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	pfnNtQueryInformationProcess fnNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(LoadLibrary("ntdll"), "NtQueryInformationProcess");

	if (fnNtQueryInformationProcess == NULL)
		return FALSE;

	DWORD dwDebugInfo = 0;
	NTSTATUS ntRet = fnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugInfo, sizeof(dwDebugInfo), NULL);
	if (ntRet == 0x00000000)
		if (dwDebugInfo != 0)
			return TRUE;

	return FALSE;
}

/*
	NtSetInformationThread called with
	ThreadInformationClass set to 0x11
	(ThreadHideFromDebugger constant), the
	thread will be detached from the debugger
*/
static BOOL MyNtSetInformationProcess(VOID) {
	/*
		Dynamically load the function since it's
		only available with this method (AFAIK)
	*/
	typedef NTSTATUS(NTAPI *pfnNtSetInformationProcess)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG);
	pfnNtSetInformationProcess fnNtSetInformationProcess = (pfnNtSetInformationProcess)GetProcAddress(LoadLibrary("ntdll"), "NtSetInformatinnThread");

	if (fnNtSetInformationProcess == NULL)
		return FALSE;

	const int ThreadHideFromDebugger = 0x11;
	NTSTATUS ntRet = fnNtSetInformationProcess(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
	if (ntRet == 0x00000000)
		return TRUE;

	return FALSE;
}

/*
	Calling CloseHandle on an invalid handle
	when the process is being debugged will
	throw a STATUS_INVALID_HANDLE exception
*/
static BOOL MyCloseHandle(VOID) {
	__try {
		CloseHandle((HANDLE)0xDEADBEEF);
	}
	__except (STATUS_INVALID_HANDLE) {
		return TRUE;
	}

	return FALSE;
}

static BOOL MyOutputDebugString(VOID) {
	DWORD dwError = 0x1337;
	SetLastError(dwError);
	OutputDebugString("Hello world");

	if (GetLastError() == dwError)
		return TRUE;

	return FALSE;
}

// check this
static BOOL CheckInt2D(VOID) {
	__try {
		__asm {
			int 0x2D
			xor eax, eax
			add eax, 2
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	return TRUE;
}

// check for debuggers
BOOL CheckForDebuggers(VOID) {
	BOOL bResult = FALSE;

	// IsDebuggerPresent
	return MyIsDebuggerPresent();

	// prevent debuggers from receiving events
	// NtSetInformationThread
	// DetachFromDebugger

	// NtGlobalFlag
	//return CheckNtGlobalFlag();

	// heap flags

	// NtQueryInformationProcess

	// CloseHandle(INVALID_HANDLE_VALUE)

	// OutputDebugString

#ifdef FIND_WINDOW
	// windows with names of debuggers
#endif

	// processes with names of debuggers

	// timing
	// rdtsc

	// int 2dh
	// need to set up own exception handler

	return bResult;
}
#endif
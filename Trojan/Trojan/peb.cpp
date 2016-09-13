#include <Windows.h>

DWORD GetPEB(VOID) {
	return __readfsdword(0x30);
}
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

/*
	Anti-sandboxing
		- extended sleeping
		- user interaction
			- mouse events
		- artefact checks
		- stalling code (executing useless instructions to 
		  emulate process execution

*/

#include <string.h>
#include <Windows.h>
#include <winternl.h>
#include <VersionHelpers.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include "main.h"
#include "anti.h"

LPSTR DebuggerNames[] = {
	"odbg",
	"ollydbg",
	"ida",
	"immunity",
	"softice", 
	"radare",
	"gdb"
	/* needs more names */
};

LPSTR MonitoringToolNames[] = {
	"procmon",
	"processhacker",
	"procexp",
	"wireshark"
	/* needs more names */
};

LPSTR VMRegistryKeys[] = {
	"SOFTWARE",						/* check for VMware Inc.*/
	"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
	"SYSTEM\\CurrentControlSet\\CriticalDeviceDatabase\\root#vmwvmchihostdev",
	"SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers"
};

LPSTR VMProcessNames[] = {
	/* VMware */
	"vmtoolsd",
	"vmwaretrat",
	"vmwareuser",
	"vmacthlp",
	/* Virtual Box */
	"vboxservice",
	"vboxtray"
};

LPSTR VMSys32DriversFileNames[] = {
	/* VMware */
	"vmmouse",
	"vm3dgl",
	"vmdum",
	"vm3dver",
	"vmtray",
	"vmtoolshook",
	"vmmousever",
	"vmhgfs",
	"vmguestlibjava",
	"driversvmhgfs", //?
	/* Virtual Box */
	"vboxmouse",
	"vboxguest",
	"vboxsf",
	"vboxvideo",
	"vboxdisp",
	"vboxhook",
	"vboxmrxnp",
	"vboxogl",
	"vboxoglarrayspu",
	"vboxoglcrutil",
	"vboxoglerrorspu",
	"vboxoglfeedbackspu",
	"vboxoglpackspu",
	"vboxoglpassthroughspu",
	"vboxservice",
	"vboxtray",
	"vboxcontrol"
};

// http://stackoverflow.com/questions/10385783/how-to-get-a-list-of-all-services-on-windows-7
LPSTR VMServiceNames[] = {
	/* VMware */
	"vmtools",
	"vmhgfs",
	"vmmemctl",
	"vmmouse",
	"vmrawdisk",
	"vmusbmouse",
	"vmvss",
	"vmscsi",
	"vmxnet",
	"vmx_svga",
	"vmware tools",
	"vmware physical disk helper service"
};

static VOID StringToLowerCase(LPSTR lpDest, LPSTR lpSrc) {
	strcpy(lpDest, lpSrc);

	for (int i = 0; i < (int)strlen(lpSrc); i++)
		if (lpSrc[i] >= 'A' && lpSrc[i] <= 'Z')
			lpDest[i] = lpSrc[i] + 32;
}

/*
	Enumerates all process names and checks them
	against the pre-defined strings declared above.
	If a process name contains one of the strings,
	the process will abort.
*/
static DWORD CheckProcessName(LPSTR lpName, LPSTR *lpArray, SIZE_T size) {
	for (SIZE_T i = 0; i < size; i++)
		if (strstr(lpName, lpArray[i]) != NULL)
			return TRUE;

	return FALSE;
}

static BOOL CheckVMProcessNames(VOID) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL bResult = FALSE;
	CHAR szLowerCase[MAX_PATH];
	LPPROCESSENTRY32 lppe = malloc(sizeof(PROCESSENTRY32));
	lppe->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, VMProcessNames, 6);
		if (bResult == TRUE) {
			free(lppe);
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	while (Process32Next(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, VMProcessNames, 6);
		if (bResult == TRUE)
			break;
	}

	free(lppe);
	CloseHandle(hSnapshot);

	return bResult;
}

#ifdef ANTI_VIRTUALIZATION
BOOL CheckForVirtualization(VOID) {
	CheckVMProcessNames();

	return FALSE;
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

/*
	FLG_HEAP_ENABLE_TAIL_CHECK | 
	FLG_HEAP_ENABLE_FREE_CHECK | 
	FLG_HEAP_VALIDATE_PARAMETERS
*/
	if (dwFlag & 0x70)
		return TRUE;

	return FALSE;
}

// not working yet
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
static BOOL MyNtSetInformationThread(VOID) {
	/*
		Dynamically load the function since it's
		only available with this method (AFAIK)
	*/
	typedef NTSTATUS(NTAPI *pfnNtSetInformationProcess)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG);
	pfnNtSetInformationProcess fnNtSetInformationProcess = (pfnNtSetInformationProcess)GetProcAddress(LoadLibrary("ntdll"), "NtSetInformationThread");

	if (fnNtSetInformationProcess == NULL)
		return FALSE;

	const int ThreadHideFromDebugger = 0x11;
	NTSTATUS ntRet = fnNtSetInformationProcess(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
	if (ntRet)
		return TRUE;

	return FALSE;
}

/*
	Calling CloseHandle on an invalid handle
	when the process is being debugged will
	throw a STATUS_INVALID_HANDLE exception
*/
static BOOL MyCloseHandle(HANDLE h) {
	__try {
		CloseHandle((HANDLE)h);
	}
	__except (STATUS_INVALID_HANDLE) {
		return TRUE;
	}

	return FALSE;
}

/*
	Win2K and WinXP only
*/
static BOOL MyOutputDebugString(VOID) {
	DWORD dwError = 0x1337;
	SetLastError(dwError);
	OutputDebugString("Hello world");

	if (GetLastError() == dwError)
		return TRUE;

	return FALSE;
}

/*
	If the process is being debugged and the int 
	2Dh instruction is executed with the trace 
	flag, no exception will be generated the following 
	byte will be skipped and execution will continue
*/
static BOOL CheckInt2D(VOID) {
	__try {
		__asm {
			int 0x2D
			mov eax, 1    // anti-trace
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;     // process not being debugged
	}

	return TRUE;
}

/*
	Uses precision timer to calculate the delta
	time between intructions. By raising an exception, 
	it forces extra time onto the debugging process
	hence creating a larger delta
*/
static BOOL RdtscTimer(DWORD dwTimeThreshold) {
	DWORD64 dwInitialTime = 0;

	__try {
		dwInitialTime = __rdtsc();
		__asm {
			xor eax, eax
			div eax
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		// do nothing
	}

	if (__rdtsc() - dwInitialTime > dwTimeThreshold)
		return FALSE;
	else
		return TRUE;
}

/*
	Enumerates all windows and checks all window names 
	for any of the pre-defined strings declared above. 
	Returns TRUE if one exists, else FALSE
*/
static BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	CHAR szWindowText[MAX_PATH];
	CHAR szLowerCase[MAX_PATH];

	if (GetWindowText(hWnd, szWindowText, MAX_PATH) != 0) {
		//Debug("Found window: %s\n", szWindowText);
		StringToLowerCase(szLowerCase, szWindowText);
		for (int i = 0; i < 5; i++)
			if (strstr(szLowerCase, DebuggerNames[i]) != NULL) {
				*(PBOOL)lParam = TRUE;
				return FALSE;
			}

		for (int i = 0; i < 4; i++)
			if (strstr(szLowerCase, MonitoringToolNames[i]) != NULL) {
				*(PBOOL)lParam = TRUE;
				return FALSE;
			}
	}

	return TRUE;
}

/*
	Starts a window enumeration
*/
static BOOL CheckWindowNames(VOID) {
	BOOL bResult = FALSE;
	EnumWindows(EnumWindowsProc, (LPARAM)&bResult);

	return bResult;
}

// multithread this on an infinite loop?
// only 32-bit processes
static BOOL CheckProcessNames(VOID) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	BOOL bResult = FALSE;
	CHAR szLowerCase[MAX_PATH];
	LPPROCESSENTRY32 lppe = malloc(sizeof(PROCESSENTRY32));
	lppe->dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, lppe) == TRUE) {
		StringToLowerCase(szLowerCase, lppe->szExeFile);
		//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
		bResult = CheckProcessName(szLowerCase, DebuggerNames, 5) | CheckProcessName(szLowerCase, MonitoringToolNames, 4);
		if (bResult == TRUE) {
			free(lppe);
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}

	while (Process32Next(hSnapshot, lppe) == TRUE) {
			StringToLowerCase(szLowerCase, lppe->szExeFile);
			//Debug("Original process: %s\nLowercased: %s", lppe->szExeFile, szLowerCase);
			bResult = CheckProcessName(szLowerCase, DebuggerNames, 5) | CheckProcessName(szLowerCase, MonitoringToolNames, 4);
			if (bResult == TRUE)
				break;
	}

	free(lppe);
	CloseHandle(hSnapshot);

	return bResult;
}

// check for debuggers
BOOL CheckForDebuggers(VOID) {
	BOOL bResult = FALSE;

#ifdef FIND_DEBUG_WINDOW_NAMES
	// windows with names of debuggers
	bResult |= CheckWindowNames();
#endif

	// processes with names of debuggers 
	// and monitoring tools
	bResult |= CheckProcessNames();

	// direct checks for debugging activity
	bResult |=
		// IsDebuggerPresent
		MyIsDebuggerPresent() |
		// NtGlobalFlag
		CheckNtGlobalFlag() |
		// NtQueryInformationProcess
		MyNtQueryInformationProcess() |
		// NtQueryInformationProcess
		MyNtQueryInformationProcess() |
		// CloseHandle(INVALID_HANDLE)
		MyCloseHandle((HANDLE)0xDEADBEEF) |
		// int 2Dh
		CheckInt2D();

	// prevent debuggers from receiving events
	// DetachFromDebugger
	//MyNtSetInformationThread();

	// heap flags

	// OutputDebugString
	if ((IsWindowsXPOrGreater() || IsWindowsXPSP1OrGreater || IsWindowsXPSP2OrGreater() || IsWindowsXPSP3OrGreater) && !IsWindowsVistaOrGreater()) {
		bResult |= MyOutputDebugString();
	}

	// timing
	//RdtscTimer(0x10000);

	return bResult;
}
#endif
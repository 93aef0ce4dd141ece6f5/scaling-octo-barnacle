#pragma once
#ifndef ANTI_H
#define ANTI_H

#define ANTI_VIRTUALIZATION
//#define ANTI_DEBUGGING

#define FIND_DEBUG_WINDOW_NAMES

BOOL CheckForVirtualization(VOID);
BOOL CheckForDebuggers(VOID);

#endif // !ANTI_H

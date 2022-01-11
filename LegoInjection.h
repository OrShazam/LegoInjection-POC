#include "common.h"
#include "scrap.h"



BOOL InjectShellcode(HANDLE hProcess,HANDLE hThread,PBYTE shellcode, size_t shellcodeSize);

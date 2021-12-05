
#include "common.h"
typedef struct {
	HMODULE hModule;
	LPVOID Base;
	DWORD ImageSize;
} ScraperData, *PScraperData;

BOOL FillScraperData(PScraperData, const char*);
BOOL FindBytes(PScraperData, BYTE*, size_t,LPVOID*);

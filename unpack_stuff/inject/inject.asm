.386
.model flat,stdcall
option casemap:none

include \masm32\include\windows.inc 
include \masm32\include\kernel32.inc 
includelib \masm32\lib\kernel32.lib

.data
PInfo 			PROCESS_INFORMATION <> 
SInfo			STARTUPINFOA		<>

Kernel			db		"kernel32.dll", 0
LLib			db		"LoadLibraryA", 0
exe_name		db 		"DungeonSiege.exe", 0
dll_name		db		"crunch_unpacker.dll", 0
Addr_name		dd		0

.code
start:
	invoke GetStartupInfo, addr SInfo 
	invoke CreateProcess, addr exe_name, NULL, NULL, NULL, FALSE,
						CREATE_SUSPENDED, NULL, NULL, addr SInfo, addr PInfo
	invoke VirtualAllocEx, PInfo.hProcess, 0, 100h, MEM_COMMIT, PAGE_READWRITE
	mov [Addr_name], eax
	invoke WriteProcessMemory, PInfo.hProcess, Addr_name, addr dll_name, LENGTHOF dll_name, NULL
	invoke GetModuleHandleA, addr Kernel
	invoke GetProcAddress, eax, addr LLib
	invoke CreateRemoteThread, PInfo.hProcess, NULL, 0, eax, [Addr_name], 0, NULL
	invoke WaitForSingleObject, eax, INFINITE
	invoke ResumeThread, PInfo.hThread
	
exit:
	invoke ExitProcess, 0
end start
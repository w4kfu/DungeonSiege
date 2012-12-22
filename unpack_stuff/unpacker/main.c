#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "dbg.h"
#include "pestuff.h"
#include "fixIAT.h"

static PVOID protVectoredHandler;
static DWORD dwTextAddr;
static DWORD dwTextSize;


void    fixthisshit(PIMAGE_DOS_HEADER pDosHeader, DWORD dwOEP)
{
    PBYTE   dwActual;
    PDWORD  pAddress;
    DWORD   dwNearIAT;
    DWORD   dwStartIAT;
    DWORD   dwEndIAT;
    DWORD   dwSizeIAT = 0;
    struct dll *NewDLL = NULL;

    init_fixIAT();
    for (dwActual = dwOEP/*dwTextAddr*/; dwActual < dwTextAddr + dwTextSize - 5; dwActual++)
    {
        if ((dwActual[0] == 0xFF) && ((dwActual[1] == 0x25)  || (dwActual[1] == 0x15)))
        {
            pAddress = *(PDWORD*)(dwActual + 2);
            if ((!IsRealBadReadPtr(pAddress, 4)) && (!IsRealBadReadPtr((void*)*pAddress, 4)))
            {
                DWORD address = *pAddress;
                dwNearIAT = pAddress;
                print_call_jmp(dwActual, pAddress, address, dwActual[1], NULL);
                break;
            }
        }
    }
    dwStartIAT = getstartIAT(pAddress);
    dwEndIAT = getendIAT(pAddress);
    print_iat_info(dwStartIAT, dwEndIAT);
    // LET'S GO !!!
    fixiat(dwStartIAT, dwEndIAT, &NewDLL);
    // GO DUMP !!!
    dump(dwOEP, NewDLL, dwStartIAT);
}

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    static BOOL stepInto = FALSE;
    DWORD oldProtect;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        DWORD address = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        DWORD eip = ExceptionInfo->ContextRecord->Eip;


        VirtualProtect((LPVOID)dwTextAddr, dwTextSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        if ((eip == address) && (address >= dwTextAddr) && (address < (dwTextAddr + dwTextSize)))
        {
            MessageBoxA(0, "Fuck Yeah !", "OEP Found",0);
            print_text_addr(eip, eip);
            fixthisshit(GetModuleHandle(0), eip);
            MessageBoxA(0, "KILL DA PROCESSS !", "KILL THEM ALL",0);
            TerminateProcess(GetCurrentProcess(), 0);
        }
        else
        {
            stepInto = TRUE;
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if ((ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) && (stepInto))
    {
        VirtualProtect((LPVOID)dwTextAddr, dwTextSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &oldProtect);
        stepInto = FALSE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void go_oep(PIMAGE_DOS_HEADER pDosHeader)
{
    DWORD dwOldProtect;
    DWORD dwTextBase;

    dwTextBase = (DWORD)GetSectionInfo((BYTE*)pDosHeader, ".text", SEC_VIRT_ADDR);
    dwTextSize = (DWORD)GetSectionInfo((BYTE*)pDosHeader, ".text", SEC_VIRT_SIZE);
    print_text_addr((DWORD)pDosHeader + dwTextBase, dwTextSize);
    if (dwTextBase == 0 || dwTextSize == 0)
        return;
    dwTextAddr = (DWORD)pDosHeader + dwTextBase;
    dwTextSize = 0x10000; // DBG STYLE
    protVectoredHandler = AddVectoredExceptionHandler(0,ProtectionFaultVectoredHandler);
    VirtualProtect((LPVOID)dwTextAddr, dwTextSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    PBYTE base;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(GetModuleHandleA("crunch_unpacker.dll"));
            base = (PBYTE)GetModuleHandleA(NULL);
            pDosHeader = (PIMAGE_DOS_HEADER)base;
            if (pDosHeader->e_magic != 'ZM')
                return FALSE;
            pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + base);
            if (pPE->Signature != 'EP')
                return FALSE;
            go_oep(pDosHeader);
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

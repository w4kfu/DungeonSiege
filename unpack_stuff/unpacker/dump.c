#include "dump.h"

DWORD AlignSize(DWORD size, DWORD alignement)
{
    return (size % alignement == 0) ? size : ((size / alignement) + 1 ) * alignement;
}

DWORD AlignCurseur(PBYTE pDump, DWORD *curseur)
{

}

PBYTE AllocAndCopy(DWORD dwBase, DWORD *dwAllocSize)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    PBYTE pDump = NULL;

    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pPE = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));

    *dwAllocSize = pSectionHeaders[pPE->FileHeader.NumberOfSections-1].VirtualAddress + pSectionHeaders[pPE->FileHeader.NumberOfSections-1].Misc.VirtualSize;

    pDump = VirtualAlloc(NULL, *dwAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDump)
        return NULL;
    memcpy(pDump, dwBase, dwAllocSize);
    return pDump;
}

BOOL dump(DWORD dwOEP, struct dll *NewDLL, DWORD dwStartIAT)
{
    DWORD dwBase;
    DWORD dwLen;
    BYTE modulePath[MAX_PATH + 8];
    PBYTE pDump;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSection;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    DWORD curseur, i;
    HANDLE hFile;
    DWORD NbByteWritten;
    PBYTE IAT = NULL;
    DWORD dwAllocSize = 0;
    DWORD dwRVAIAT = 0;

    dwBase = (DWORD)GetModuleHandle(NULL);
    if (((dwLen = GetModuleFileNameA((HMODULE) dwBase, modulePath, MAX_PATH + 1)) >= MAX_PATH) || (!dwLen))
        return FALSE;
    if (!(pDump = AllocAndCopy(dwBase, &dwAllocSize)))
        return FALSE;
    pDosHeader = (PIMAGE_DOS_HEADER)pDump;
    pPE = (PIMAGE_NT_HEADERS)(pDump + pDosHeader->e_lfanew);
    pSection = (PIMAGE_SECTION_HEADER)((PCHAR)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));

    pPE->OptionalHeader.FileAlignment = 0x200;
    for (curseur = AlignSize(pPE->OptionalHeader.SizeOfHeaders, pPE->OptionalHeader.FileAlignment) - 1; ! pDump[curseur]; curseur --);

    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
    dwRVAIAT = AlignSize(pSectionHeaders[pPE->FileHeader.NumberOfSections - 1].VirtualAddress + pSectionHeaders[pPE->FileHeader.NumberOfSections - 1].Misc.VirtualSize,
                         pPE->OptionalHeader.SectionAlignment);
    IAT = Reconstruct(dwStartIAT, NewDLL, dwRVAIAT);
    memcpy(pDump, dwBase, dwAllocSize);
    curseur = AlignSize(curseur + 1, pPE->OptionalHeader.FileAlignment);
    pPE->OptionalHeader.SizeOfHeaders = curseur;
    for (i = 0; i < pPE->FileHeader.NumberOfSections; i++)
    {
        memcpy(pDump + curseur, pDump + pSection[i].VirtualAddress, pSection[i].Misc.VirtualSize);
        pSection[i].PointerToRawData = curseur;
        curseur += pSection[i].Misc.VirtualSize - 1;
        //AlignCurseur(pDump, &curseur);
        while ((pDump[curseur] == 0) && (((int)curseur) >= -1))
           curseur--;
        curseur = AlignSize(curseur + 1, pPE->OptionalHeader.FileAlignment);
        pSection[i].SizeOfRawData = curseur - pSection[i].PointerToRawData;
    }

    strcpy(pSection[pPE->FileHeader.NumberOfSections].Name, ".suce");
    pSection[pPE->FileHeader.NumberOfSections].PointerToRawData = curseur;
    pSection[pPE->FileHeader.NumberOfSections].Misc.VirtualSize = AlignSize(computeSizeIAT(NewDLL),
                                                                            pPE->OptionalHeader.SectionAlignment);
    pSection[pPE->FileHeader.NumberOfSections].VirtualAddress = dwRVAIAT;
    pSection[pPE->FileHeader.NumberOfSections].Characteristics = 0xE0000060;

    memcpy(pDump + curseur, IAT, pSection[pPE->FileHeader.NumberOfSections].Misc.VirtualSize);
    curseur += pSection[pPE->FileHeader.NumberOfSections].Misc.VirtualSize - 1;
    while ((pDump[curseur] == 0) && (((int)curseur) >= -1))
        curseur--;
    curseur = AlignSize(curseur + 1, pPE->OptionalHeader.FileAlignment);
    pSection[pPE->FileHeader.NumberOfSections].SizeOfRawData = curseur - pSection[pPE->FileHeader.NumberOfSections].PointerToRawData;

    pPE->FileHeader.NumberOfSections += 1;
    pPE->OptionalHeader.DataDirectory[1].VirtualAddress = dwRVAIAT;
    pPE->OptionalHeader.DataDirectory[1].Size = computeSizeIAT(NewDLL);
    pPE->OptionalHeader.AddressOfEntryPoint = dwOEP - (DWORD)GetModuleHandle(0);
    pPE->OptionalHeader.SizeOfImage += AlignSize(computeSizeIAT(NewDLL),
                                                pPE->OptionalHeader.SectionAlignment);

    modulePath[dwLen - 4] = '-';
    modulePath[dwLen - 3] = 'd';
    modulePath[dwLen - 2] = 'u';
    modulePath[dwLen - 1] = 'm';
    modulePath[dwLen] = 'p';
    modulePath[dwLen + 1] = 'e';
    modulePath[dwLen + 2] = 'd';
    modulePath[dwLen + 3] = '.';
    modulePath[dwLen + 4] = 'e';
    modulePath[dwLen + 5] = 'x';
    modulePath[dwLen + 6] = 'e';
    modulePath[dwLen + 7] = 0;

    if ((hFile = CreateFileA(modulePath,(GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_READ,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(hFile, pDump, curseur, &NbByteWritten, NULL);
    if (NbByteWritten != curseur)
        return FALSE;
    return TRUE;
}

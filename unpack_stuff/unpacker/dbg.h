#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <windows.h>

#include "fixIAT.h"

#define FILE_DBG "dbg_msg.txt"

void print_text_addr(DWORD dwAddr, DWORD dwSize);

void print_dll(struct dll *ldll);

void print_call_jmp(DWORD dwAddrText, DWORD dwDestAddress, DWORD dwPAddress, enum TYPE_INSTRU t, struct dll *dll);

void print_iat_info(DWORD dwStart, DWORD dwEnd);

void print_bug_api_found(char *pName, DWORD dwAddr, DWORD dwPAddress);

void print_size_new_iat(struct dll *ldll);

void hex_dump(void *data, int size);

enum TYPE_INSTRU
{
    CALL = 0x25,
    JUMP = 0x15
};

#endif // __DBG_H__

#include "dbg.h"

FILE *fp = NULL;
int initialized = 0;

void open_file(void)
{
    if (!initialized)
    {
        fp = fopen(FILE_DBG, "w");
        initialized = 1;
    }
    else
        fp = fopen(FILE_DBG, "a");
}

void print_text_addr(DWORD dwAddr, DWORD dwSize)
{
    open_file();
    fprintf(fp, "[+] .text section addr : %X\n", dwAddr);
    fprintf(fp, "[+] .text section size : %X\n", dwSize);
    fclose(fp);
}

void print_iat_info(DWORD dwStart, DWORD dwEnd)
{
    open_file();
    fprintf(fp, "[+] IAT Start : %X\n", dwStart);
    fprintf(fp, "[+] IAT End : %X\n", dwEnd);
    fclose(fp);
}

void print_api(struct api *lapi)
{
    while (lapi)
    {
        fprintf(fp, "\t[+] Name : %s, Address : %X, Ordinal : %X\n", lapi->pName, lapi->dwAddress, lapi->wOrdinal);
        lapi = lapi->next;
    }
}

void print_dll(struct dll *ldll)
{
    while (ldll)
    {
        open_file();
        fprintf(fp, "--------------------\n");
        fprintf(fp, "[+] Module Name : %s\n", ldll->pName);
        fprintf(fp, "[+] Module Base : %X\n", ldll->dwBase);
        fprintf(fp, "[+] Module SizeOfImage : %X\n", ldll->dwSizeOfImage);
        fprintf(fp, "\t API\n");
        print_api(ldll->pAPI);
        fprintf(fp, "--------------------\n");
        ldll = ldll->next;
        fclose(fp);
    }
}

void print_call_jmp(DWORD dwAddrText, DWORD dwDestAddress, DWORD dwPAddress, enum TYPE_INSTRU t, struct dll *dll)
{
    open_file();
    switch (t)
    {
        case CALL:
            fprintf(fp, "%X : CALL [%X] = %X\n", dwAddrText, dwDestAddress, dwPAddress);
            break;
        case JUMP:
            fprintf(fp, "%X : JMP [%X] = %X\n", dwAddrText, dwDestAddress, dwPAddress);
            break;
    }

    fclose(fp);
}

void print_bug_api_found(char *pName, DWORD dwAddr, DWORD dwPAddress)
{
    open_file();
    fprintf(fp, "[-] BUG API : [%X] = %X ::: NAME = %s\n", dwAddr, dwPAddress, pName);
    fclose(fp);
}

void print_size_new_iat(struct dll *ldll)
{
    struct api *lapi = NULL;
    DWORD   dwCountapi = 0;
    DWORD   dwCountdll = 0;
    DWORD   dwDLLNamesLength = 0;
    DWORD   dwAPINamesLength = 0;

    while (ldll)
    {
        lapi = ldll->pAPI;
        dwDLLNamesLength += strlen(ldll->pName) + 1;
        dwCountdll++;
        while (lapi)
        {
            dwCountapi++;
            dwAPINamesLength += strlen(lapi->pName) + 3;
            lapi = lapi->next;
        }
        ldll = ldll->next;
    }
    open_file();
    fprintf(fp, "[+] Number of DLL entry IAT : %d\n", dwCountdll);
    fprintf(fp, "[+] Number of API entry IAT : %d\n", dwCountapi);
    fprintf(fp, "[+] DLLNamesLength : %d\n", dwDLLNamesLength);
    fprintf(fp, "[+] APINamesLength : %d\n", dwAPINamesLength);
    fclose(fp);
}

void hex_dump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

	unsigned char *p =(unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    open_file();
    for(n = 1; n <= size; n++)
	{
        if (n % 16 == 1)
		{
            /* store address for this line */
            sprintf_s(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
        c = *p;
        if (isprint(c) == 0)
		{
            c = '.';
        }
        /* store hex str (for left side) */
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if (n % 16 == 0)
		{
            /* line completed */
            fprintf(fp, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
		else if (n % 8 == 0)
		{
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0)
	{
        /* print rest of buffer if not empty */
        fprintf(fp, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    fclose(fp);
}

#ifndef __DUMP_H__
#define __DUMP_H__

#include <stdio.h>
#include <windows.h>

#include "fixIAT.h"

BOOL dump(DWORD dwOEP, struct dll *NewDLL, DWORD dwStartIAT);

#endif // __DUMP_H__

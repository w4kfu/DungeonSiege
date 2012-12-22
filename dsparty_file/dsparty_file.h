#ifndef __DSPARTYFILE_H__
#define __DSPARTYFILE_H__

#include "TankStructure.h"

enum MODE
{
    READ_ONLY = 0,
    CRAFT
};

struct config_dsparty
{
    PBYTE   file;
    BYTE    bMode;
    PBYTE   ofile;
    HANDLE  HFile;
    HANDLE  HMap;
    PBYTE   bMap;
    struct ds_header *header;
    struct ds_dirset *dirset;
    struct ds_fileset *fileset;

    struct ds_direntry *direntry;
};

#endif /* __DSPARTYFILE_H__ */


#ifndef __TANKVIEWER_H__
#define __TANKVIEWER_H__

#include <windows.h>
#include <stdio.h>
#include "dsparty_file.h"

struct ds_header
{
  BYTE		m_ProductId[4];
  BYTE		m_TankId[4];
  DWORD		m_HeaderVersion;
  DWORD		m_DirSetOffset;
  DWORD		m_FileSetOffset;
  DWORD		m_IndexSize;
  DWORD		m_DataOffset;
  BYTE		m_ProductVersion[12];
  BYTE		m_MinimumVersion[12];
  DWORD		m_Priority;
  DWORD		m_Flags;
  BYTE		m_CreatorId[4];
  GUID		m_GUID;
  DWORD		m_IndexCRC32;
  DWORD		m_DataCRC32;
  SYSTEMTIME	m_UtcBuildTime;
  WCHAR		m_CopyrightText[100];
  WCHAR		m_BuildText[100];
  WCHAR		m_TitleText[100];
  WCHAR		m_AuthorText[40];
  BYTE		*m_DescriptionText;
};

struct	NString
{
  WORD	m_Length;
  BYTE	m_Text[1];
};

struct ds_direntry
{
    DWORD    m_ParentOffset;
    DWORD    m_ChildCount;
    FILETIME m_FileTime;
    struct NString  m_Name;
    DWORD    m_ChildOffsets[1];
};

struct ds_fileentry
{
    DWORD    m_ParentOffset;                            // where's the base of our parent DirEntry?
    DWORD    m_Size;                                    // size of resource
    DWORD    m_Offset;                                  // offset to data from top of data section
    DWORD    m_CRC32;                                   // CRC-32 of just this resource
    FILETIME m_FileTime;                                // last modified timestamp of file when it was added
    WORD     m_Format;                                  // data format (eDataFormat)
    WORD     m_Flags;                                   // flags (eFileFlags)
    struct NString  m_Name;                                    // what's my name?
};

struct ds_dirset
{
    DWORD    m_Count;
    DWORD    m_Offsets[1];
    //struct ds_direntry m_DirEntries[1];
};

struct	ds_fileset
{

  DWORD	m_Count;
  DWORD	m_Offsets[1];
  //struct ds_fileentry m_FileEntries[1];                 // sorted alphabetically overall
};

void print_headerinfo(struct ds_header *header);
int check_sig(struct ds_header *header);
void print_dirset_info(struct ds_dirset *dirset);
void print_fileset_info(struct ds_fileset *fileset);
void print_direntry_info(struct ds_direntry *direntry);
void print_fileentry_info(struct ds_fileentry *fileentry);
DWORD compute_size_index(struct config_dsparty *ds_party);

#endif /* __TANKVIEWER_H__ */

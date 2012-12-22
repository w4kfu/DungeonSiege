#include "TankStructure.h"

void print_headerinfo(struct ds_header *header)
{
    printf("m_HeaderVersion = 0x%X\n", header->m_HeaderVersion);
    printf("m_DirSetOffset = 0x%X\n", header->m_DirSetOffset);
    printf("m_FileSetOffset = 0x%X\n", header->m_FileSetOffset);
    printf("m_IndexSize = 0x%X\n", header->m_IndexSize);
    printf("m_DataOffset = 0x%X\n", header->m_DataOffset);
    // m_ProductVersion
    // m_MinimumVersion
    printf("m_Priority = 0x%X\n", header->m_Priority);
    printf("m_Flags = 0x%X\n", header->m_Flags);
    // m_CreatorId[4];
    // m_GUID;
    printf("m_IndexCRC32 = 0x%X\n", header->m_IndexCRC32);
    printf("m_DataCRC32 = 0x%X\n", header->m_DataCRC32);
    // m_UtcBuildTime;
    printf("m_CopyrightText = %S\n", header->m_CopyrightText);
    printf("m_BuildText = %S\n", header->m_BuildText);
    printf("m_TitleText = %S\n", header->m_TitleText);
    printf("m_AuthorText = %S\n", header->m_AuthorText);
}

int check_sig(struct ds_header *header)
{
    if (strncmp(header->m_ProductId, "DSig", 4))
    {
        fprintf(stderr, "[-] ProductID check failed\n");
        return 0;
    }
    if (strncmp(header->m_TankId, "Tank", 4))
    {
        fprintf(stderr, "[-] TankID check failed\n");
        return 0;
    }
    return 1;
}

void print_dirset_info(struct ds_dirset *dirset)
{
    DWORD dwCount;

    printf("-- DirSet Info --\n");
    printf("m_Count = %X\n", dirset->m_Count);
    for (dwCount = 0; dwCount < dirset->m_Count; dwCount++)
    {
        printf("m_Offsets[%d] = %X\n", dwCount, dirset->m_Offsets[dwCount]);
    }
}

void print_fileset_info(struct ds_fileset *fileset)
{
    DWORD dwCount;

    printf("-- FileSet Info --\n");
    printf("m_Count = %X\n", fileset->m_Count);
    for (dwCount = 0; dwCount < fileset->m_Count; dwCount++)
    {
        printf("m_Offsets[%d] = %X\n", dwCount, fileset->m_Offsets[dwCount]);
    }
}

void print_direntry_info(struct ds_direntry *direntry)
{
    DWORD dwCount;

    printf("-- DirEntry Info --\n");
    printf("m_ParentOffset = %X\n", direntry->m_ParentOffset);
    printf("m_ChildCount = %X\n", direntry->m_ChildCount);
    //printf(m_FileTime)
    printf("m_Name.m_Length = %X\n", direntry->m_Name.m_Length);
    if (direntry->m_Name.m_Length)
        printf("m_Name = %s\n", direntry->m_Name.m_Text);
    for (dwCount = 0; dwCount < direntry->m_ChildCount; dwCount++)
    {
        printf("m_ChildOffsets[%d] = %X\n", dwCount, direntry->m_ChildOffsets[dwCount]);
    }
}

void print_fileentry_info(struct ds_fileentry *fileentry)
{
    printf("-- FileEntry Info --\n");
    printf("m_ParentOffset = %X\n", fileentry->m_ParentOffset);
    printf("m_Size = %X\n", fileentry->m_Size);
    printf("m_Offset = %X\n", fileentry->m_Offset);
    printf("m_CRC32 = %X\n", fileentry->m_CRC32);
    //printf(m_FileTime)
    printf("m_Format = %X\n", fileentry->m_Format);
    printf("m_Flags = %X\n", fileentry->m_Flags);
    printf("m_Name = %s\n", fileentry->m_Name.m_Text);
}

DWORD compute_size_index(struct config_dsparty *ds_party)
{
    DWORD dwSize = 0;

    // Header
    //dwSize += sizeof (struct ds_header);
    // Dir Entry
    //dwSize += sizeof (struct ds_dirset);
    //dwSize += ds_party->dirset->m_Count * sizeof (struct ds_direntry);
    dwSize += 4;
    dwSize += 4 * ds_party->dirset->m_Count;
    dwSize += ds_party->dirset->m_Count * (sizeof (DWORD) + sizeof (DWORD) + sizeof (FILETIME) + sizeof (struct NString));

    // File Entry
    //dwSize += sizeof (struct ds_fileset);
    //dwSize += ds_party->fileset->m_Count * sizeof (struct ds_fileentry);
    dwSize += 4;
    dwSize += 4 * ds_party->fileset->m_Count;
    dwSize += ds_party->fileset->m_Count * sizeof (struct ds_fileentry);

    printf("Size = %X\n", dwSize);
    return dwSize;
}

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tchar.h>

#include "dsparty_file.h"
#include "TankStructure.h"
#include "getopt.h"

void help(void)
{
    printf("DsParty Reader\n");
    printf("Usage : %s [OPTION] *.dsparty\n");
    printf("-r : Parse only the file\n");
    printf("-c : Craft malicious dsparty file\n");
    printf("-o : Output file\n");
    exit(EXIT_SUCCESS);
}

int parse_arg(int argc, char *argv[], struct config_dsparty *config)
{
    char format[] = "hrco:";
    extern char *optarg;
    extern int optind, optopt;
    int optch;

    while ((optch = getopt(argc, argv, format)) != -1)
    {
        switch (optch)
        {
            case 'h':
                help();
            case 'r':
                config->bMode |= READ_ONLY;
                break;
            case 'c':
                config->bMode |= CRAFT;
                break;
            case 'o':
                config->ofile = optarg;
                break;
            case ':':
                fprintf(stderr, "Option -%c requires an operand\n", optopt);
                help();
            case '?':
                help();
        }
    }
    if (optind < argc)
    {
        //while (optind < argc)
        config->file = argv[optind++];
    }
    if (config->file == 0)
    {
        fprintf(stderr, "No imput file specified\n");
        return 0;
    }
    return 1;
}

int open_and_map(struct config_dsparty *config)
{
    config->HFile = CreateFile(config->file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL );
    if (config->HFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "[-] CreateFile() failed : %X\n", GetLastError());
        return 0;
    }

    config->HMap = CreateFileMapping(config->HFile, NULL, PAGE_READONLY, 0, 0, 0);
    if (config->HMap == NULL)
    {
        fprintf(stderr, "[-] CreateFileMapping() failed : %X\n", GetLastError());
        return 0;
    }
    config->bMap = (PBYTE)MapViewOfFile(config->HMap, FILE_MAP_READ, 0, 0, 0);
    if (config->bMap == NULL)
    {
        fprintf(stderr, "[-] MapViewOfFile() failed : %X\n", GetLastError());
        return 0;
    }
    return 1;
}

void clean(struct config_dsparty *config)
{
    CloseHandle(config->HFile);
    CloseHandle(config->HMap);
    CloseHandle(config->bMap);
}

void setval(struct config_dsparty *config)
{
    config->header = (struct ds_header*)config->bMap;
    config->dirset = (struct ds_dirset*)(config->bMap + config->header->m_DirSetOffset);
    config->fileset = (struct ds_fileset*)(config->bMap + config->header->m_FileSetOffset);

    // TO CHANGE
    config->direntry = (struct ds_direntry*)(config->bMap + config->header->m_DirSetOffset + config->dirset->m_Offsets[0]);
}

int main(int argc, char *argv[])
{
    struct config_dsparty config;

    memset(&config, 0, sizeof (struct config_dsparty));
    if (!parse_arg(argc, argv, &config))
        exit(EXIT_FAILURE);
    printf("Size = %d\n", sizeof (struct ds_header));
    if (!open_and_map(&config))
        exit(EXIT_FAILURE);
    if (!check_sig((struct ds_header*)config.bMap))
        exit(EXIT_FAILURE);
    setval(&config);
    print_headerinfo(config.header);
    //print_dirset_info(config.dirset);
    //print_fileset_info(config.fileset);

    //print_direntry_info(config.direntry);
    compute_size_index(&config);
    clean(&config);
    system("pause");
    return 0;
}

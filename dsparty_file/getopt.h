#ifndef GETOPT_H_
#define GETOPT_H_


#ifdef __cplusplus
extern "C" {
#endif


extern char* optarg;
extern int optind;
extern int opterr;
extern int optopt;

int getopt(int argc, char** argv, char* optstr);


#ifdef __cplusplus
}
#endif


#endif /* GETOPT_H_ */


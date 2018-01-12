/**HashCheck********************************************************************

  File        HaskCheck.c

  Resume      Compute the most used hashes

  Description This library only for the moment:

  Autor       Raúl San Martín Aniceto

  Copyright (c) 2018 Raúl San Martín Aniceto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <errno.h>

#include "HashCheck.h"

/*---------------------------------------------------------------------------*/
/* Constant declarations                                                     */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Type declarations                                                         */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Structure declarations                                                    */
/*---------------------------------------------------------------------------*/

typedef struct{
  int help;
  int bin;
  int quiet;
  int version;
  int check;
  int no_valid_optn;
}args_t;

static struct option long_options[] = {
  {"help",    no_argument,       0, 'h'},
  {"binary",  no_argument,       0, 'b'},
  {"text",    no_argument,       0, 't'},
  {"quiet",   no_argument,       0, 'q'},
  {"version", no_argument,       0, 'v'},
  {"check",   no_argument,       0, 'c'},
  {0, 0, 0, 0}
};

/*---------------------------------------------------------------------------*/
/* Variable declarations                                                     */
/*---------------------------------------------------------------------------*/

uint8_t read_stdin  = 0;
uint8_t quiet_flag  = 0;

/*---------------------------------------------------------------------------*/
/* Macro declarations                                                        */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Static function prototypes                                                */
/*---------------------------------------------------------------------------*/

void print_help(char *program_name);

void print_version();

args_t process_args(int num, char **arguments);

int isDir(const char *path);

/*---------------------------------------------------------------------------*/
/* Main                                                                      */
/*---------------------------------------------------------------------------*/

int main(int argc, char **argv){
  args_t arguments = process_args(argc, argv);
  if(opterr){
    return -1;
  }

  if(arguments.no_valid_optn){
    printf("%s: unrecognized option '%s'\n", argv[0],
              argv[arguments.no_valid_optn]);
    printf("Try '%s --help' for more information.\n", argv[0]);
    return -1;
  }

  if(argc <= (optind + 1)){
    read_stdin = 1;
  }

  if(arguments.help){
    print_help(argv[0]);
    return 0;
  }

  if(arguments.version){
    print_version();
    return 0;
  }

  FILE *fp = NULL;
  uint8_t *msg = NULL;
  size_t checksum_len;
  size_t file_len;

  char mode[3] = "r\0\0";

  if(arguments.quiet){
    quiet_flag = 1;
  }
  if(arguments.check){
    fp = fopen(argv[optind], "r");

    if(isDir(argv[optind])){
      errno = EISDIR;
      fclose(fp);
    }

    if((fp == NULL) || errno){
      printf("%s: %s: %s\n", argv[0], argv[optind], strerror(errno));
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }else{
    if(read_stdin == 0){
      if(arguments.bin){
        strcpy(mode, "rb");
      }else{
        strcpy(mode, "r");
      }

      fp = fopen(argv[optind+1], mode);

      if(isDir(argv[optind+1])){
        errno = EISDIR;
        fclose(fp);
      }

      if((fp == NULL) || errno){
        printf("%s: %s: %s\n", argv[0], argv[optind+1], strerror(errno));
        return -1;
      }

      fseek(fp, 0, SEEK_END);
      file_len = ftell(fp);
      fseek(fp, 0, SEEK_SET);

      msg = malloc(file_len + 1);
      fread(msg, file_len, 1, fp);
      fclose(fp);

      msg[file_len] = 0;
    }else{
      char buff;
      size_t chars_readed = 0;
      while((buff = getc(stdin)) != EOF){
        chars_readed++;
        msg = realloc(msg, chars_readed + 1);
        msg[chars_readed - 1] = buff;
      }
      if(chars_readed == 0){
        msg = malloc(sizeof(uint8_t));
      }
      msg[chars_readed] = '\0';
      file_len = chars_readed;
    }
  }

  uint8_t digest[64] = {0};

  if(!strcmp(argv[optind], "md5")){
    checksum_len = 16;
    if(md5_sum(msg, file_len, digest)){
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }else if(!strcmp(argv[optind], "sha1")){
    checksum_len = 20;
    if(sha1_sum(msg, file_len, digest)){
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }
  else if(!strcmp(argv[optind], "sha224")){
    checksum_len = 28;
    if(sha224_sum(msg, file_len, digest)){
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }else if(!strcmp(argv[optind], "sha256")){
    checksum_len = 32;
    if(sha256_sum(msg, file_len, digest)){
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }
  else if(!strcmp(argv[optind], "sha384")){
    checksum_len = 48;
    if(sha384_sum(msg, file_len, digest)){
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }else if(!strcmp(argv[optind], "sha512")){
    checksum_len = 64;
    if(sha512_sum(msg, file_len, digest)){
      if(msg != NULL){
        free(msg);
      }
      return -1;
    }
  }else{
    printf("%s: %s: No valid command\n", argv[0], argv[optind]);
    free(msg);
    return -1;
  }

  int i;
  for(i = 0; i<checksum_len; i++){
    printf("%02x", digest[i]);
  }
  if(argv[optind+1]){
    printf("  %s\n", argv[optind+1]);
  }else{
    printf("  -\n");
  }

  if(msg != NULL){
    free(msg);
  }
}

/*---------------------------------------------------------------------------*/
/* Static function definitions                                               */
/*---------------------------------------------------------------------------*/

void print_help(char *program_name){
    printf("usage: %s [ARGUMENTS]... [OPTION] [FILE]...\n", program_name);
    printf("Print or check the most used checksums.\n\n");
    printf("With no FILE, or when FILE is -, read standard input.\n\n");
    printf("Arguments:\n");
    printf("\t-b, --binary         read in binary mode\n");
    printf("\t-c, --check          read checksums from the FILEs and check them\n");
    printf("\t-t, --text           read in text mode (by default)\n");
    printf("\t    --quiet          don't print OK for each successfully verified file\n");
    printf("\t-h, --help           display this help and exit\n");
    printf("\t-v, --version        output version information and exit\n\n");
    printf("Options:\n");
    printf("\t-Message Digest Algorithm:\n");
    printf("\n\tmd5                  Print or check MD5 (128-bit) checksums\n");
    printf("\n\t-Secure Hash Algorithm 1:\n");
    printf("\n\tsha1                 Print or check SHA-1 (160-bit) checksums\n");
    printf("\n\t-Secure Hash Algorithm 2:\n");
    printf("\n\tsha224               Print or check SHA-224 checksums\n");
    printf("\tsha256               Print or check SHA-256 checksums\n");
    printf("\tsha384               Print or check SHA-384 checksums\n");
    printf("\tsha512               Print or check SHA-512 checksums\n");
}

void print_version(){
  printf("HashCheck v0.1.4 ");
  printf("https://github.com/MrAnnix/HashCheck\n\n");
  printf("Copyright (c) 2018 Raúl San Martín Aniceto.\n");
  printf("MIT License\n");
  printf("<https://opensource.org/licenses/MIT>.\n");
  printf("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND\n\n");
  printf("Writen by Raul San Martin Aniceto.\n");
}

args_t process_args(int num, char **arguments){
  args_t result;
  int option_index;
  int c;
  opterr = 0;

  result.help = 0;
  result.bin = 0;//0 for text
  result.quiet = 0;
  result.version = 0;
  result.check = 0;
  result.no_valid_optn = 0;

  while((c = getopt_long(num, arguments,"hbtqvc:",long_options,
            &option_index)) != -1){
    switch(c){
      case 'h':
        result.help = 1;
      break;

      case 'b':
        result.bin  = 1;
      break;

      case 't':
        result.bin  = 0;
      break;

      case 'q':
        result.quiet = 1;
      break;

      case 'v':
        result.version = 1;
      break;

      case 'c':
        result.check = 1;
      break;

      case '?':
        result.no_valid_optn = optind - 1;
      break;

      default:
        abort ();
    }
  }
  return result;
}

int isDir(const char *path){
  struct stat statbuf;
  if(stat(path, &statbuf) != 0){
    return 0;
  }
  return S_ISDIR(statbuf.st_mode);
}

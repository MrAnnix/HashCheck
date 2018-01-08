/**HashCheck********************************************************************

  File        md5.c

  Resume      Compute md5 sum.
              Based on Wikipedia example (https://en.wikipedia.org/wiki/MD5)

  See also    HashCheck.h

  Autor       Raúl San Martín Aniceto (https://github.com/MrAnnix)

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

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

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


/*---------------------------------------------------------------------------*/
/* Variable declarations                                                     */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Macro declarations                                                        */
/*---------------------------------------------------------------------------*/

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

/*---------------------------------------------------------------------------*/
/* Static function prototypes                                                */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Function definitions                                                      */
/*---------------------------------------------------------------------------*/

int md5_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[16]){
  //Initialize variables:
  uint32_t h0 = 0x67452301; //A
  uint32_t h1 = 0xEFCDAB89; //B
  uint32_t h2 = 0x98BADCFE; //C
  uint32_t h3 = 0x10325476; //D

  //s specifies the per-round shift amounts
  uint32_t s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

  //Use binary integer part of the sines of integers (Radians) as constants:
  uint32_t k[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
                    0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
                    0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
                    0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
                    0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
                    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
                    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
                    0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
                    0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
                    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

  //Pre-processing:
  uint8_t *msg = NULL;

  size_t new_len;
  new_len = initial_len*8 + 1;
  new_len += (512-((new_len+64)%512))%512;
  new_len /= 8;

  msg = calloc(new_len + sizeof(uint64_t), sizeof(uint8_t));
  if(msg == NULL){//calloc failed
    return -1;
  }

  memcpy(msg, initial_msg, initial_len);
  msg[initial_len] = 0x80; // appending single bit to the message

  uint64_t bits_len = 8*initial_len; //append original length in bits mod 2^64
  memcpy(msg + new_len, &bits_len, sizeof(uint64_t));

  //Process the message in successive 512-bit chunks:
  int offset;
  //for each 512-bit chunk of padded message
  for(offset = 0; offset < new_len; offset += (512/8)){
    //break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
    uint32_t *m = (uint32_t *)(msg + offset);

    // Initialize hash value for this chunk:
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;

    //Main loop:
    int i;
    for(i = 0; i < 64; i++){
      int f, g;

      if(i < 16){
        f = (b & c) | ((~b) & d);
        g = i;
      }else if(i < 32){
        f = (d & b) | ((~d) & c);
        g = (5*i + 1) % 16;
      }else if(i < 48){
        f = b ^ c ^ d;
        g = (3*i + 5) % 16;
      }else{
        f = c ^ (b | (~d));
        g = (7*i) % 16;
      }

      //Be wary of the below definitions of a,b,c,d
      uint32_t tmp = d;
      d = c;
      c = b;
      b = b + LEFTROTATE((a + f + k[i] + m[g]), s[i]);
      a = tmp;
    }
    //Add this chunk's hash to result so far:
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
  }

  memcpy(digest     , &h0, sizeof(uint32_t));
  memcpy(digest +  4, &h1, sizeof(uint32_t));
  memcpy(digest +  8, &h2, sizeof(uint32_t));
  memcpy(digest + 12, &h3, sizeof(uint32_t));

  free(msg);

  return 0;
}

/*---------------------------------------------------------------------------*/
/* Static function definitions                                               */
/*---------------------------------------------------------------------------*/

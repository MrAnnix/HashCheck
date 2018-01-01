/**HashCheck********************************************************************

  File        sha1.c

  Resume      Compute sha1 sum.
              Based on Wikipedia example (https://en.wikipedia.org/wiki/SHA-1)

  See also    HashCheck.h

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

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <byteswap.h>

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

int sha1_sum(uint8_t *initial_msg, size_t initial_len, uint8_t *digest){
  //Initialize variables:
  uint32_t h0 = 0x67452301; //A
  uint32_t h1 = 0xEFCDAB89; //B
  uint32_t h2 = 0x98BADCFE; //C
  uint32_t h3 = 0x10325476; //D
  uint32_t h4 = 0xC3D2E1F0; //E

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

  //append original length in bits mod 2^64
  uint64_t bits_len = __bswap_64(8*initial_len);
  memcpy(msg + new_len, &bits_len, sizeof(uint64_t));

  //Process the message in successive 512-bit chunks:
  size_t offset;
  //for each 512-bit chunk of padded message
  for(offset = 0; offset < new_len; offset += (512/8)){
    int i;
    uint32_t temp;
    //break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
    uint32_t w[80];
    for(i = 0; i < 16; i++){
      w[i]  = msg[i * 4 + 0 + offset] << 24;
      w[i] |= msg[i * 4 + 1 + offset] << 16;
      w[i] |= msg[i * 4 + 2 + offset] << 8;
      w[i] |= msg[i * 4 + 3 + offset];
    }

    //Extend the sixteen 32-bit words into eighty 32-bit words:
    for(i = 16; i< 80; i++){
      w[i] = LEFTROTATE((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
    }

    // Initialize hash value for this chunk:
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;

    //Main loop:
    for(i = 0; i < 80; i++){
      int f, k;

      if(i < 20){
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      }else if(i < 40){
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      }else if(i < 60){
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      }else{
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }

      //Be wary of the below definitions of a,b,c,d
      temp = LEFTROTATE(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = LEFTROTATE(b, 30);
      b = a;
      a = temp;
    }

    //Add this chunk's hash to result so far:
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  digest[ 0] = (h0 >> 24) & 0xff;
  digest[ 1] = (h0 >> 16) & 0xff;
  digest[ 2] = (h0 >>  8) & 0xff;
  digest[ 3] = (h0      ) & 0xff;
  digest[ 4] = (h1 >> 24) & 0xff;
  digest[ 5] = (h1 >> 16) & 0xff;
  digest[ 6] = (h1 >>  8) & 0xff;
  digest[ 7] = (h1      ) & 0xff;
  digest[ 8] = (h2 >> 24) & 0xff;
  digest[ 9] = (h2 >> 16) & 0xff;
  digest[10] = (h2 >>  8) & 0xff;
  digest[11] = (h2      ) & 0xff;
  digest[12] = (h3 >> 24) & 0xff;
  digest[13] = (h3 >> 16) & 0xff;
  digest[14] = (h3 >>  8) & 0xff;
  digest[15] = (h3      ) & 0xff;
  digest[16] = (h4 >> 24) & 0xff;
  digest[17] = (h4 >> 16) & 0xff;
  digest[18] = (h4 >>  8) & 0xff;
  digest[19] = (h4      ) & 0xff;

  free(msg);

  return 0;
}

/*---------------------------------------------------------------------------*/
/* Static function definitions                                               */
/*---------------------------------------------------------------------------*/

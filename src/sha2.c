/**HashCheck********************************************************************

  File        sha2.c

  Resume      Compute sha2 sum.
              Based on Wikipedia example (https://en.wikipedia.org/wiki/SHA-2)

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
#define RIGHTROTATE(x,c) (((x) >> (c)) | ((x) << (32 - (c))))
#define EP0(x) (RIGHTROTATE(x, 2) ^ RIGHTROTATE(x,13) ^ RIGHTROTATE(x,22))
#define EP1(x) (RIGHTROTATE(x, 6) ^ RIGHTROTATE(x,11) ^ RIGHTROTATE(x,25))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (RIGHTROTATE(x,7) ^ RIGHTROTATE(x,18) ^ ((x) >> 3))
#define SIG1(x) (RIGHTROTATE(x,17) ^ RIGHTROTATE(x,19) ^ ((x) >> 10))

/*---------------------------------------------------------------------------*/
/* Static function prototypes                                                */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Function definitions                                                      */
/*---------------------------------------------------------------------------*/

int sha256_sum(uint8_t *initial_msg, size_t initial_len, uint8_t *digest){
  //Initialize variables:
  uint32_t h0 = 0x6a09e667; //A
  uint32_t h1 = 0xbb67ae85; //B
  uint32_t h2 = 0x3c6ef372; //C
  uint32_t h3 = 0xa54ff53a; //D
  uint32_t h4 = 0x510e527f; //E
  uint32_t h5 = 0x9b05688c; //F
  uint32_t h6 = 0x1f83d9ab; //G
  uint32_t h7 = 0x5be0cd19; //H

  uint32_t k[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
                    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
                    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
                    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
                    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

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
    uint32_t t1;
    uint32_t t2;
    //break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
    uint32_t w[64];
    for(i = 0; i < 16; i++){
      w[i]  = msg[i * 4 + 0 + offset] << 24;
      w[i] |= msg[i * 4 + 1 + offset] << 16;
      w[i] |= msg[i * 4 + 2 + offset] << 8;
      w[i] |= msg[i * 4 + 3 + offset];
    }

    //Extend the sixteen 32-bit words into eighty 32-bit words:
    for(i = 16 ; i< 64; i++){
      w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    // Initialize hash value for this chunk:
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    uint32_t f = h5;
    uint32_t g = h6;
    uint32_t h = h7;

    //Main loop:
    for(i = 0; i < 64; i++){
      t1 = h + EP1(e) + CH(e,f,g) + k[i] + w[i];
		  t2 = EP0(a) + MAJ(a, b, c);
      h = g;
		  g = f;
		  f = e;
		  e = d + t1;
		  d = c;
		  c = b;
		  b = a;
		  a = t1 + t2;
    }

    //Add this chunk's hash to result so far:
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
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
  digest[20] = (h5 >> 24) & 0xff;
  digest[21] = (h5 >> 16) & 0xff;
  digest[22] = (h5 >>  8) & 0xff;
  digest[23] = (h5      ) & 0xff;
  digest[24] = (h6 >> 24) & 0xff;
  digest[25] = (h6 >> 16) & 0xff;
  digest[26] = (h6 >>  8) & 0xff;
  digest[27] = (h6      ) & 0xff;
  digest[28] = (h7 >> 24) & 0xff;
  digest[29] = (h7 >> 16) & 0xff;
  digest[30] = (h7 >>  8) & 0xff;
  digest[31] = (h7      ) & 0xff;

  free(msg);

  return 0;
}

/*---------------------------------------------------------------------------*/
/* Static function definitions                                               */
/*---------------------------------------------------------------------------*/

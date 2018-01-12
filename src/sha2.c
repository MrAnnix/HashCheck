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

#include <stdio.h>
#include <inttypes.h>

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

#define LEFTROTATE64(x, c) (((x) << (c)) | ((x) >> (64 - (c))))
#define RIGHTROTATE64(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define EP0(x) (RIGHTROTATE(x, 2) ^ RIGHTROTATE(x,13) ^ RIGHTROTATE(x,22))
#define EP1(x) (RIGHTROTATE(x, 6) ^ RIGHTROTATE(x,11) ^ RIGHTROTATE(x,25))
#define SIG0(x) (RIGHTROTATE(x, 7) ^ RIGHTROTATE(x,18) ^ ((x) >>  3))
#define SIG1(x) (RIGHTROTATE(x,17) ^ RIGHTROTATE(x,19) ^ ((x) >> 10))

#define EP0_512(x) (RIGHTROTATE64(x, 28) ^ RIGHTROTATE64(x,34)\
            ^ RIGHTROTATE64(x, 39))
#define EP1_512(x) (RIGHTROTATE64(x, 14) ^ RIGHTROTATE64(x,18)\
            ^ RIGHTROTATE64(x, 41))
#define SIG0_512(x) (RIGHTROTATE64(x, 1) ^ RIGHTROTATE64(x, 8) ^ ((x) >> 7))
#define SIG1_512(x) (RIGHTROTATE64(x,19) ^ RIGHTROTATE64(x,61) ^ ((x) >> 6))

/*---------------------------------------------------------------------------*/
/* Static function prototypes                                                */
/*---------------------------------------------------------------------------*/

uint128_t __bswap_128(uint128_t num);

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
  new_len = initial_len*8 + 1 + sizeof(uint64_t)*8;
  new_len += (512-((new_len)%512))%512;
  new_len /= 8;

  msg = calloc(new_len, sizeof(uint8_t));
  if(msg == NULL){//calloc failed
    return -1;
  }

  memcpy(msg, initial_msg, initial_len);
  msg[initial_len] = 0x80; // appending single bit to the message

  //append original length in bits mod 2^64
  uint64_t bits_len = __bswap_64(8*initial_len);
  memcpy(msg + new_len - sizeof(uint64_t), &bits_len, sizeof(uint64_t));

  //Process the message in successive 512-bit chunks:
  size_t offset;
  //for each 512-bit chunk of padded message
  for(offset = 0; offset < new_len; offset += (512/8)){
    int i;
    uint32_t t1;
    uint32_t t2;
    //break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
    uint32_t w[64] = {0};
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

int sha512_sum(uint8_t *initial_msg, size_t initial_len, uint8_t *digest){
  //Initialize variables:
  uint64_t h0 = 0x6a09e667f3bcc908; //A
  uint64_t h1 = 0xbb67ae8584caa73b; //B
  uint64_t h2 = 0x3c6ef372fe94f82b; //C
  uint64_t h3 = 0xa54ff53a5f1d36f1; //D
  uint64_t h4 = 0x510e527fade682d1; //E
  uint64_t h5 = 0x9b05688c2b3e6c1f; //F
  uint64_t h6 = 0x1f83d9abfb41bd6b; //G
  uint64_t h7 = 0x5be0cd19137e2179; //H

  uint64_t k[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
                    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
                    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
                    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
                    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
                    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
                    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
                    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
                    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
                    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
                    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
                    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
                    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
                    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
                    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
                    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
                    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

  //Pre-processing:
  uint8_t *msg = NULL;

  size_t new_len;
  new_len = initial_len*8 + 1 + sizeof(uint128_t)*8;
  new_len += (1024-(new_len%1024))%1024;
  new_len /= 8;

  msg = calloc(new_len, sizeof(uint8_t));
  if(msg == NULL){//calloc failed
    return -1;
  }

  memcpy(msg, initial_msg, initial_len);
  msg[initial_len] = 0x80; // appending single bit to the message

  //append original length in bits mod 2^128
  uint128_t bits_len = __bswap_128(8*(uint128_t)initial_len);
  memcpy(msg + new_len - sizeof(uint128_t), &bits_len, sizeof(uint128_t));

  //Process the message in successive 1024-bit chunks:
  size_t offset;
  //for each 1024-bit chunk of padded message
  for(offset = 0; offset < new_len; offset += (1024/8)){
    int i;
    uint64_t t1;
    uint64_t t2;
    //break chunk into sixteen 64-bit words w[j], 0 ≤ j ≤ 15
    uint64_t w[80] = {0};
    for(i = 0; i < 16; i++){
      w[i]  = (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 0 + offset]) << 56;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 1 + offset]) << 48;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 2 + offset]) << 40;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 3 + offset]) << 32;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 4 + offset]) << 24;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 5 + offset]) << 16;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 6 + offset]) << 8;
      w[i] |= (0xFFFFFFFFFFFFFFFF & msg[i * 8 + 7 + offset]);
    }

    //Extend the sixteen 64-bit words into eighty 64-bit words:
    for(i = 16 ; i< 80; i++){
      w[i] = SIG1_512(w[i - 2]) + w[i - 7] + SIG0_512(w[i - 15] + w[i - 16]);
    }

    // Initialize hash value for this chunk:
    uint64_t a = h0;
    uint64_t b = h1;
    uint64_t c = h2;
    uint64_t d = h3;
    uint64_t e = h4;
    uint64_t f = h5;
    uint64_t g = h6;
    uint64_t h = h7;

    //Main loop:
    printf("\n              A/E              B/F              C/G              D/H \n");
    for(i = 0; i < 80; i++){
      t1 = h + EP1_512(e) + CH(e,f,g) + k[i] + w[i];
		  t2 = EP0_512(a) + MAJ(a, b, c);
      h = g;
		  g = f;
		  f = e;
		  e = d + t1;
		  d = c;
		  c = b;
		  b = a;
		  a = t1 + t2;

      printf("t = %2u: %016lX %016lX %016lX %016lX \n", i, a, b, c, d);
      printf("        %016lX %016lX %016lX %016lX \n\n", e, f, g, h);
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

  digest[ 0] = (h0 >> 56) & 0xff;
  digest[ 1] = (h0 >> 48) & 0xff;
  digest[ 2] = (h0 >> 40) & 0xff;
  digest[ 3] = (h0 >> 32) & 0xff;
  digest[ 4] = (h0 >> 24) & 0xff;
  digest[ 5] = (h0 >> 16) & 0xff;
  digest[ 6] = (h0 >>  8) & 0xff;
  digest[ 7] = (h0      ) & 0xff;

  digest[ 8] = (h1 >> 56) & 0xff;
  digest[ 9] = (h1 >> 48) & 0xff;
  digest[10] = (h1 >> 40) & 0xff;
  digest[11] = (h1 >> 32) & 0xff;
  digest[12] = (h1 >> 24) & 0xff;
  digest[13] = (h1 >> 16) & 0xff;
  digest[14] = (h1 >>  8) & 0xff;
  digest[15] = (h1      ) & 0xff;

  digest[16] = (h2 >> 56) & 0xff;
  digest[17] = (h2 >> 48) & 0xff;
  digest[18] = (h2 >> 40) & 0xff;
  digest[19] = (h2 >> 32) & 0xff;
  digest[20] = (h2 >> 24) & 0xff;
  digest[21] = (h2 >> 16) & 0xff;
  digest[22] = (h2 >>  8) & 0xff;
  digest[23] = (h2      ) & 0xff;

  digest[24] = (h3 >> 56) & 0xff;
  digest[25] = (h3 >> 48) & 0xff;
  digest[26] = (h3 >> 40) & 0xff;
  digest[27] = (h3 >> 32) & 0xff;
  digest[28] = (h3 >> 24) & 0xff;
  digest[29] = (h3 >> 16) & 0xff;
  digest[30] = (h3 >>  8) & 0xff;
  digest[31] = (h3      ) & 0xff;

  digest[32] = (h4 >> 56) & 0xff;
  digest[33] = (h4 >> 48) & 0xff;
  digest[34] = (h4 >> 40) & 0xff;
  digest[35] = (h4 >> 32) & 0xff;
  digest[36] = (h4 >> 24) & 0xff;
  digest[37] = (h4 >> 16) & 0xff;
  digest[38] = (h4 >>  8) & 0xff;
  digest[39] = (h4      ) & 0xff;

  digest[40] = (h5 >> 56) & 0xff;
  digest[41] = (h5 >> 48) & 0xff;
  digest[42] = (h5 >> 40) & 0xff;
  digest[43] = (h5 >> 32) & 0xff;
  digest[44] = (h5 >> 24) & 0xff;
  digest[45] = (h5 >> 16) & 0xff;
  digest[46] = (h5 >>  8) & 0xff;
  digest[47] = (h5      ) & 0xff;

  digest[48] = (h6 >> 56) & 0xff;
  digest[49] = (h6 >> 48) & 0xff;
  digest[50] = (h6 >> 40) & 0xff;
  digest[51] = (h6 >> 32) & 0xff;
  digest[52] = (h6 >> 24) & 0xff;
  digest[53] = (h6 >> 16) & 0xff;
  digest[54] = (h6 >>  8) & 0xff;
  digest[55] = (h6      ) & 0xff;

  digest[56] = (h7 >> 56) & 0xff;
  digest[57] = (h7 >> 48) & 0xff;
  digest[58] = (h7 >> 40) & 0xff;
  digest[59] = (h7 >> 32) & 0xff;
  digest[60] = (h7 >> 24) & 0xff;
  digest[61] = (h7 >> 16) & 0xff;
  digest[62] = (h7 >>  8) & 0xff;
  digest[63] = (h7      ) & 0xff;

  free(msg);

  return 0;
}

/*---------------------------------------------------------------------------*/
/* Static function definitions                                               */
/*---------------------------------------------------------------------------*/

uint128_t __bswap_128(uint128_t num){
  uint128_t swapped = 0;
  uint64_t aux1, aux2;

  aux1 = (num      ) & 0xffffffffffffffff;
  aux2 = (num >> 64) & 0xffffffffffffffff;

  aux1 = __bswap_64(aux1);
  aux2 = __bswap_64(aux2);

  swapped |= (uint128_t)aux1 << 64;
  swapped |= (uint128_t)aux2;

  return swapped;
}

/**HashCheck********************************************************************

  File        HashCheck.h

  Resume      Compute the most used hashes

  See also    HashCheck.c and all other c files

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
#ifndef HASH_CHECK_H
#define HASH_CHECK_H

#include <stdint.h>
#include <stddef.h>

/*---------------------------------------------------------------------------*/
/* Constant declarations                                                     */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Type declarations                                                         */
/*---------------------------------------------------------------------------*/

typedef unsigned __int128 uint128_t __attribute__((mode(TI)));

/*---------------------------------------------------------------------------*/
/* Structure declarations                                                    */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Variable declarations                                                     */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Macro declarations                                                        */
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
/* Function prototypes                                                       */
/*---------------------------------------------------------------------------*/

/**md5_sum*******************************************************************

  Resume       Computes the md5 checksum for a given message

  Description  Computes the md5 checksum for a given message. If an error ocurs,
              it returns -1 and errno is set.

  Parameters   -uint8_t *initial_msg: The initial message.
               -size_t initial_len: The length of the initial_msg.
               -uint8_t *md5sum: The result of the sum as an array of uint8_t
                                of lenght 16. 128 bits in total.

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

int md5_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[16]);

/**sha1_sum*******************************************************************

  Resume       Computes the sha1 checksum for a given message

  Description  Computes the sha1 checksum for a given message. If an error
              ocurs, it returns -1 and errno is set.

  Parameters   -uint8_t *initial_msg: The initial message.
               -size_t initial_len: The length of the initial_msg.
               -uint8_t *sha1sum: The result of the sum as an array of uint8_t
                                of lenght 20. 160 bits in total.

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

int sha1_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[20]);

/**sha224_sum*****************************************************************

  Resume       Computes the sha224 checksum for a given message

  Description  Computes the sha224 checksum for a given message. If an error
              ocurs, it returns -1 and errno is set.

  Parameters   -uint8_t *initial_msg: The initial message.
               -size_t initial_len: The length of the initial_msg.
               -uint8_t *sha1sum: The result of the sum as an array of uint8_t
                                of lenght 28. 224 bits in total.

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

int sha224_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[28]);

/**sha256_sum*****************************************************************

  Resume       Computes the sha256 checksum for a given message

  Description  Computes the sha256 checksum for a given message. If an error
              ocurs, it returns -1 and errno is set.

  Parameters   -uint8_t *initial_msg: The initial message.
               -size_t initial_len: The length of the initial_msg.
               -uint8_t *sha1sum: The result of the sum as an array of uint8_t
                                of lenght 32. 256 bits in total.

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

int sha256_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[32]);

/**sha384_sum*****************************************************************

  Resume       Computes the sha384 checksum for a given message

  Description  Computes the sha384 checksum for a given message. If an error
              ocurs, it returns -1 and errno is set.

  Parameters   -uint8_t *initial_msg: The initial message.
               -size_t initial_len: The length of the initial_msg.
               -uint8_t *sha1sum: The result of the sum as an array of uint8_t
                                of lenght 48. 384 bits in total.

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

int sha384_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[48]);

/**sha512_sum*****************************************************************

  Resume       Computes the sha512 checksum for a given message

  Description  Computes the sha512 checksum for a given message. If an error
              ocurs, it returns -1 and errno is set.

  Parameters   -uint8_t *initial_msg: The initial message.
               -size_t initial_len: The length of the initial_msg.
               -uint8_t *sha1sum: The result of the sum as an array of uint8_t
                                of lenght 64. 512 bits in total.

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

int sha512_sum(uint8_t *initial_msg, size_t initial_len, uint8_t digest[64]);

/**Function*******************************************************************

  Resume       [obligatorio]

  Description  [opcional]

  Parameters   [opcional]

  Colat. Effe. [obligatorio]

  See also     [opcional]

******************************************************************************/

#endif

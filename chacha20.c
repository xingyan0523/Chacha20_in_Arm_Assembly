/* Based on the public domain implemtation in
 * crypto_stream/chacha20/e/ref from http://bench.cr.yp.to/supercop.html
 * by Daniel J. Bernstein */

#include <stdint.h>
#include "chacha20.h"

#define ROUNDS 20

typedef uint32_t uint32;


extern int crypto_core_chacha20(
    unsigned char *out,      //r0  64  16  output
    const unsigned char *in, //r1  16   4  cnt
    const unsigned char *k,  //r2  32   8  msg
    const unsigned char *c   //r3  16   4  str
);

static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_stream_chacha20(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k)
{
  unsigned char in[16];
  unsigned char block[64];
  unsigned char kcopy[32];
  unsigned long long i;
  unsigned int u;

  if (!clen)
    return 0;

  for (i = 0; i < 32; ++i)
    kcopy[i] = k[i];
  for (i = 0; i < 8; ++i)
    in[i] = n[i];
  for (i = 8; i < 16; ++i)
    in[i] = 0;

  while (clen >= 64)
  {
    crypto_core_chacha20(c, in, kcopy, sigma);

    u = 1;

    
    for (i = 8; i < 16; ++i)
    {
      u += (unsigned int)in[i];
      in[i] = u;
      u >>= 8;
    }

    clen -= 64;
    c += 64;
  }

  if (clen)
  {
    crypto_core_chacha20(block, in, kcopy, sigma);
    for (i = 0; i < clen; ++i)
      c[i] = block[i];
  }
  return 0;
}

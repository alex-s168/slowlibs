
#include "slowlibs/chacha20.h"

static uint8_t const data[] = {0x01, 0x00, 0x02, 0x00, 0xda, 0x0e, 0xb9, 0xe9,
                               0x8b, 0x48, 0x2a, 0x18, 0x2f, 0xe3, 0xdf, 0xd3,
                               0x74, 0x39, 0xa9, 0xdd, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static uint8_t const protocol_constant[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                            0x0d, 0x0e, 0x0f, 0xfa};

static uint8_t const expected[] = {
    0xc4, 0x65, 0xe1, 0x9b, 0xe2, 0x4d, 0x02, 0x3c, 0x30, 0x9d, 0xec,
    0xfb, 0xbd, 0x83, 0x2a, 0xf8, 0x65, 0x72, 0x93, 0x9a, 0x19, 0x4a,
    0xaf, 0xfd, 0x2b, 0xa8, 0x80, 0x65, 0xe9, 0x1d, 0x9c, 0xc9,
};

static void unpadded_kcha_dirty(uint8_t state[32],
                                uint8_t const protocol_constant[16],
                                uint8_t const data[],
                                unsigned data_len,
                                int rounds)
{
  int i, chunk_len;
  slowcrypt_chacha20 cstate;
  uint8_t swap[32];

  for (i = 0; i < 32; i++)
    state[i] = 0;

  for (; (int)data_len > 0; data_len -= 32, data += 32) {
    chunk_len = data_len;
    if (chunk_len > 32)
      chunk_len = 32;

    for (i = 0; i < 32; i++)
      swap[i] = 0;
    for (i = 0; i < chunk_len; i++)
      swap[i] = data[i];

    for (i = 0; i < 32; i++)
      swap[i] ^= state[i];

    slowcrypt_hchacha(&cstate, swap, protocol_constant, state, rounds);
  }
}

int main(int argc, char** argv)
{
  uint8_t hash[32];
  int i;

  (void)argc;
  (void)argv;

  unpadded_kcha_dirty(hash, protocol_constant, (void*)data, sizeof(data) - 1,
                      8);

  for (i = 0; i < 32; i++)
    if (hash[i] != expected[i])
      return 1;

  slowcrypt_kchacha(hash, protocol_constant, (void*)data, sizeof(data) - 1, 8,
                    1);
  for (i = 0; i < 32; i++)
    if (hash[i] != expected[i])
      return 1;

  return 0;
}

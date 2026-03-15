
#include "slowlibs/chacha20.h"

static char const data[] =
    "DoNotCurrently-Use-KChaCha-InSensitive-Applications!!NeedingMoreBytes-for-"
    "getting-to-three-blocks.";

static uint8_t const protocol_constant[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                            0x0d, 0x0e, 0x0f, 0xfa};

static uint8_t const expected[] = {
    0x77, 0xa8, 0xa9, 0x15, 0x31, 0xfd, 0x0b, 0xc5, 0x8c, 0xb5, 0x28,
    0x15, 0x24, 0xfe, 0x67, 0x92, 0x85, 0x7d, 0xb4, 0x2c, 0x74, 0xb4,
    0x1f, 0x98, 0x85, 0xae, 0x76, 0x97, 0x44, 0xf6, 0x4f, 0xb4,
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

  for (; (int)data_len >= 0; data_len -= 32, data += 32) {
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
                      20);

  for (i = 0; i < 32; i++)
    if (hash[i] != expected[i])
      return 1;

  slowcrypt_kchacha(hash, protocol_constant, (void*)data, sizeof(data) - 1, 20,
                    1);
  for (i = 0; i < 32; i++)
    if (hash[i] != expected[i])
      return 1;

  return 0;
}

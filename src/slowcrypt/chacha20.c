#include <slowlibs/chacha20.h>

void slowcrypt_chacha20_deinit(slowcrypt_chacha20* state)
{
  int i;
  for (i = 0; i < 16; i++)
    *(volatile int*)&state->state[i] = 0;
}

static uint32_t slowcrypt_chacha20_read_ul32(uint8_t const* buf)
{
  uint32_t o = (uint32_t)((uint8_t const*)buf)[0];
  o |= (uint32_t)((uint8_t const*)buf)[1] << 8;
  o |= (uint32_t)((uint8_t const*)buf)[2] << 16;
  o |= (uint32_t)((uint8_t const*)buf)[3] << 24;
  return o;
}

static void slowcrypt_chacha20_write_ul32(uint8_t* buf, uint32_t val)
{
  ((uint8_t*)buf)[0] = (uint8_t)(val & 0xFF);
  ((uint8_t*)buf)[1] = (uint8_t)((val >> 8) & 0xFF);
  ((uint8_t*)buf)[2] = (uint8_t)((val >> 16) & 0xFF);
  ((uint8_t*)buf)[3] = (uint8_t)((val >> 24) & 0xFF);
}

void slowcrypt_chacha20_init(slowcrypt_chacha20* state,
                             uint8_t const key[32],
                             uint32_t block_ctr,
                             uint8_t const nonce[12])
{
  int i;

  state->state[0] = 0x61707865;
  state->state[1] = 0x3320646e;
  state->state[2] = 0x79622d32;
  state->state[3] = 0x6b206574;

  for (i = 0; i < 8; i++)
    state->state[4 + i] = slowcrypt_chacha20_read_ul32(&key[i * 4]);

  state->state[12] = block_ctr;

  for (i = 0; i < 3; i++)
    state->state[13 + i] = slowcrypt_chacha20_read_ul32(&nonce[i * 4]);
}

void slowcrypt_chacha20_serialize(uint8_t buf[64],
                                  slowcrypt_chacha20 const* state)
{
  int i;
  for (i = 0; i < 16; i++)
    slowcrypt_chacha20_write_ul32(&buf[i * 4], state->state[i]);
}

void slowcrypt_chacha20_serialize_xor(uint8_t buf[64],
                                      slowcrypt_chacha20 const* state)
{
  uint8_t swp[4];
  int i, j;

  for (i = 0; i < 16; i++) {
    slowcrypt_chacha20_write_ul32(swp, state->state[i]);
    for (j = 0; j < 4; j++)
      buf[i * 4 + j] ^= swp[j];
  }

  for (i = 0; i < 4; i++)
    swp[i] = 0;
}

void slowcrypt_chacha20_rounds(slowcrypt_chacha20* state, int num_rounds)
{
  int i;

  for (i = 0; i < num_rounds; i++) {
    if (i % 2 == 0) {
      /* column round */
      SLOWCRYPT_CHACHA20_QROUND(state->state, 0, 4, 8, 12);
      SLOWCRYPT_CHACHA20_QROUND(state->state, 1, 5, 9, 13);
      SLOWCRYPT_CHACHA20_QROUND(state->state, 2, 6, 10, 14);
      SLOWCRYPT_CHACHA20_QROUND(state->state, 3, 7, 11, 15);
    } else {
      /* diagonal round */
      SLOWCRYPT_CHACHA20_QROUND(state->state, 0, 5, 10, 15);
      SLOWCRYPT_CHACHA20_QROUND(state->state, 1, 6, 11, 12);
      SLOWCRYPT_CHACHA20_QROUND(state->state, 2, 7, 8, 13);
      SLOWCRYPT_CHACHA20_QROUND(state->state, 3, 4, 9, 14);
    }
  }
}

void slowcrypt_chacha20_run(slowcrypt_chacha20* state,
                            slowcrypt_chacha20* swap,
                            int num_rounds)
{
  int i;

  for (i = 0; i < 16; i++)
    swap->state[i] = state->state[i];

  slowcrypt_chacha20_rounds(state, num_rounds);

  for (i = 0; i < 16; i++)
    state->state[i] += swap->state[i];
}

void slowcrypt_hchacha(slowcrypt_chacha20* state,
                       uint8_t const key[32],
                       uint8_t const nonce[16],
                       uint8_t hash[32],
                       int rounds)
{
  int i;

  state->state[0] = 0x61707865;
  state->state[1] = 0x3320646e;
  state->state[2] = 0x79622d32;
  state->state[3] = 0x6b206574;

  for (i = 0; i < 8; i++)
    state->state[4 + i] = slowcrypt_chacha20_read_ul32(&key[i * 4]);

  for (i = 0; i < 4; i++)
    state->state[12 + i] = slowcrypt_chacha20_read_ul32(&nonce[i * 4]);

  slowcrypt_chacha20_rounds(state, rounds);

  for (i = 0; i < 4; i++)
    slowcrypt_chacha20_write_ul32(&hash[i * 4], state->state[i]);

  for (i = 0; i < 4; i++)
    slowcrypt_chacha20_write_ul32(&hash[i * 4 + 16], state->state[i + 12]);
}

void slowcrypt_chacha20_block(slowcrypt_chacha20 state[2],
                              uint8_t const key[32],
                              uint32_t block_ctr,
                              uint8_t const nonce[12],
                              uint8_t data[64])
{
  slowcrypt_chacha20_init(state, key, block_ctr, nonce);
  slowcrypt_chacha20_run(state, &state[1], 20);
  slowcrypt_chacha20_serialize_xor(data, state);
}

void slowcrypt_chacha20_poly1305_key_gen(uint8_t out[32],
                                         uint8_t const key[32],
                                         uint8_t const* nonce,
                                         int nonce_len)
{
  int i;
  uint8_t nonce_buf[12];
  slowcrypt_chacha20 state, state2;

  if (nonce_len == 8) {
    /* 64-bit nonce, prepend 4 zero bytes */
    nonce_buf[0] = 0;
    nonce_buf[1] = 0;
    nonce_buf[2] = 0;
    nonce_buf[3] = 0;
    for (i = 0; i < 8; i++)
      nonce_buf[4 + i] = nonce[i];
    nonce = nonce_buf;
  } else {
    for (i = 0; i < 12; i++)
      nonce_buf[i] = nonce[i];
    nonce = nonce_buf;
  }

  slowcrypt_chacha20_init(&state, key, 0, nonce);
  slowcrypt_chacha20_run(&state, &state2, 20);

  for (i = 0; i < 8; i++)
    slowcrypt_chacha20_write_ul32(&out[i * 4], state.state[i]);

  slowcrypt_chacha20_deinit(&state);
  slowcrypt_chacha20_deinit(&state2);
}

void slowcrypt_kchacha(uint8_t state[32],
                       uint8_t const protocol_constant[16],
                       uint8_t const data[],
                       unsigned data_len,
                       int rounds,
                       int unpadded)
{
  int i, chunk_len;
  slowcrypt_chacha20 cstate;
  uint8_t swap[32];
  int add_trailing_block = !unpadded;

  for (i = 0; i < 32; i++)
    state[i] = 0;

  for (; (int)data_len >= 0; data_len -= 32, data += 32) {
    chunk_len = data_len;
    if (chunk_len > 32)
      chunk_len = 32;

    for (i = 0; i < chunk_len; i++)
      swap[i] = data[i];
    for (; i < 31; i++)
      swap[i] = 0;

    if (!unpadded && chunk_len != 32) {
      add_trailing_block = 0;
      swap[31] = 32 - chunk_len;
    }

    for (i = 0; i < 32; i++)
      swap[i] ^= state[i];

    slowcrypt_hchacha(&cstate, swap, protocol_constant, state, rounds);
  }

  if (add_trailing_block) {
    for (; i < 31; i++)
      swap[i] = state[i];
    swap[31] = 32 ^ state[i];

    slowcrypt_hchacha(&cstate, swap, protocol_constant, state, rounds);
  }

  slowcrypt_chacha20_deinit(&cstate);
  for (i = 0; i < 32; i++)
    ((volatile uint8_t*)swap)[i] = 0;
  *(volatile int*)&chunk_len = 0;
  *(volatile int*)&add_trailing_block = 0;
}

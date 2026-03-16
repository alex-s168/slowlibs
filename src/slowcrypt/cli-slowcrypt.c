#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "slowlibs/chacha20.h"

#define SLOWCRYPT_POLY1305_IMPL
#include "slowlibs/poly1305.h"

#define SLOWCRYPT_SYSTEMRAND_IMPL
#include "slowlibs/systemrand.h"

struct algo
{
  char const* name;
  void (*run)(char**);
};

static FILE* file_open(char const* path)
{
  FILE* fp;

  if (!strcmp(path, "-"))
    return stdin;

  fp = fopen(path, "rb");
  if (!fp) {
    fprintf(stderr, "Could not open %s\n", path);
    exit(1);
  }
  return fp;
}

static void file_close(FILE* p)
{
  if (!p)
    return;
  if (p == stdout || p == stdin || p == stderr)
    return;
  fclose(p);
}

static int anyeq__impl(char const* str, char const** opts)
{
  for (; *opts; opts++)
    if (!strcmp(str, *opts))
      return 1;
  return 0;
}
#define anyeq(str, ...) anyeq__impl(str, (char const*[]){__VA_ARGS__, 0})

static char const* parse_hex_prefix(char const* msg)
{
  if (*msg == 'h')
    msg++;
  else if (msg[0] == '0' && msg[1] == 'x')
    msg++;

  return msg;
}

static uint8_t parse_hex_nibble(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 0xA;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 0xA;
  fprintf(stderr, "Not a hexadecimal number!\n");
  exit(1);
}

static uint8_t parse_hex(char const** msg)
{
  uint8_t res = parse_hex_nibble(*(*msg)++);
  if (**msg) {
    res <<= 4;
    res |= parse_hex_nibble(*(*msg)++);
  }
  return res;
}

static void parse_hex2buf(uint8_t* buf,
                          unsigned int buflen,
                          char const* label,
                          char const* hex)
{
  unsigned int num = 0;
  hex = parse_hex_prefix(hex);
  for (; num < buflen && *hex; num++)
    buf[num] = parse_hex(&hex);
  if (num != buflen || *hex) {
    fprintf(stderr, "Expected %s to be %u (hexadecimal) bytes!\n", label,
            buflen);
    exit(1);
  }
}

static unsigned long file_read_chunk(FILE* file,
                                     uint8_t* buf,
                                     unsigned long buflen)
{
  unsigned long n;
  if (feof(file))
    return 0;
  n = fread(buf, 1, buflen, file);
  if (ferror(file)) {
    fprintf(stderr, "File read error!");
    exit(1);
  }
  return n;
}

static void* file_read_all(FILE* file, unsigned long* lenout)
{
  void* all = 0;
  void* allnew;
  unsigned long all_len = 0;
  void* buf = malloc(8 * 1024);
  unsigned long clen;
  if (!buf) {
    fprintf(stderr, "malloc fail (8KiB)\n");
    exit(1);
  }

  while (!feof(file)) {
    clen = file_read_chunk(file, buf, 8 * 1024);
    if (!clen)
      break;
    allnew = realloc(all, all_len + clen);
    if (!allnew) {
      free(all);
      fprintf(stderr, "malloc fail (%lu B)\n", all_len + clen);
      exit(1);
    }
    all = allnew;
    memcpy(all + all_len, buf, clen);
    all_len += clen;
  }

  free(buf);

  *lenout = all_len;
  return all;
}

static void parse_rng_args(unsigned long* oLimit,
                           char** oSeed,
                           char const* rngName,
                           char const* description,
                           char** args)
{
  static char const help[] =
      "%s [--limit <num bytes>] [--seed] [seed]\n\nWhen a seed is given, the "
      "given seed will be used INSTEAD of the system rng!\n\n%s";
  int npos = 0;

  *oLimit = 0;
  *oSeed = 0;

  for (; *args; args++) {
    if (anyeq(*args, "-h", "--h", "-help", "--help")) {
      printf(help, rngName, description);
      exit(0);
    } else if (anyeq(*args, "-limit", "--limit", "-n")) {
      args++;
      sscanf(*args, "%lu", oLimit);
    } else if (anyeq(*args, "-seed", "--seed")) {
    } else if (npos == 0 && ++npos) {
      *oSeed = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }
}

static void run_kchacha(char** args)
{
  static char const help[] =
      "kchacha [--rounds N] <protocol-constant>\n"
      "\n"
      "Run the KChaCha hash function\n"
      "\n"
      "Defaults to 20 rounds\n"
      "\n"
      "Protocol constant is a hex value, that should be unique to each "
      "aplication,\n"
      " and NEVER be zero!\n";
  uint8_t hash[32], protocol_constant[16];
  char const* protocol_constant_hex;
  int nrounds = 20;
  int npos = 0;
  int i;
  uint8_t* input;
  unsigned long len;

  for (; *args; args++) {
    if (anyeq(*args, "-h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (anyeq(*args, "-r", "-rounds", "--rounds") && args[1]) {
      args++;
      nrounds = atoi(*args);
    } else if (npos == 0 && ++npos) {
      protocol_constant_hex = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (npos < 1) {
    fprintf(stderr, "Missing arguments!\n");
    exit(1);
  }

  parse_hex2buf(protocol_constant, 16, "protocol-constant",
                protocol_constant_hex);

  input = file_read_all(stdin, &len);
  slowcrypt_kchacha(hash, protocol_constant, input, len, nrounds, 0);

  for (i = 0; i < 32; i++)
    printf("%02x", hash[i]);
  printf("\n");
}

static void run_balloon_kchacha(char** args)
{
  static char const help[] =
      "balloon-kchacha [--chacha-rounds N] [--space Bytes] [--balloon-rounds "
      "N] <protocol-constant>\n"
      "\n"
      "Run the balloon-hash function using KChaCha as inner function, with "
      "system entropy as salt\n"
      "\n"
      "Defaults to 20 ChaCha rounds, 1 Balloon round, and 256MiB space.\n"
      "\n"
      "Protocol constant is a hex value, that should be unique to each "
      "aplication,\n"
      " and NEVER be zero!\n";
  uint8_t hash[32], salt[32], protocol_constant[16];
  char const* protocol_constant_hex;
  int chacha_rounds = 20, balloon_rounds = 1, space = 256 * 1024 * 1024;
  int npos = 0;
  int i;
  uint8_t* input;
  unsigned long len;

  for (; *args; args++) {
    if (anyeq(*args, "-h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (anyeq(*args, "-balloon-rounds", "--balloon-rounds") && args[1]) {
      args++;
      balloon_rounds = atoi(*args);
    } else if (anyeq(*args, "-chacha-rounds", "--chacha-rounds") && args[1]) {
      args++;
      chacha_rounds = atoi(*args);
    } else if (anyeq(*args, "-s", "-space", "--space") && args[1]) {
      args++;
      space = atoi(*args);
    } else if (npos == 0 && ++npos) {
      protocol_constant_hex = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (npos < 1) {
    fprintf(stderr, "Missing arguments!\n");
    exit(1);
  }

  parse_hex2buf(protocol_constant, 16, "protocol-constant",
                protocol_constant_hex);

  input = file_read_all(stdin, &len);

  if (slowcrypt_systemrand(salt, sizeof salt,
                           SLOWCRYPT_SYSTEMRAND__BAIL_IF_INSECURE)) {
    fprintf(stderr, "slowcrypt_systemrand error\n");
    exit(1);
  }

  if (slowcrypt_balloon_kchacha(hash, protocol_constant, input, len, salt,
                                sizeof salt, space, balloon_rounds,
                                chacha_rounds, 0)) {
    fprintf(stderr, "oom\n");
    exit(1);
  }

  printf("For salt: ");
  for (i = 0; i < sizeof salt; i++)
    printf("%02x", salt[i]);
  printf("\n");

  printf("Hash: ");
  for (i = 0; i < 32; i++)
    printf("%02x", hash[i]);
  printf("\n");
}

static void run_chacha20_core(char** args)
{
  static char const help[] =
      "chacha20-core <key> <counter> <nonce>\n"
      "\n"
      "Run the ChaCha20 block function\n";
  char const *key, *nonce;
  unsigned int npos = 0;
  unsigned int nb;
  unsigned long lu;
  uint32_t counter;
  slowcrypt_chacha20 state[2];
  uint8_t buf[64];
  uint8_t keyb[32];
  uint8_t nonceb[12];

  if (!*args) {
    printf("%s", help);
    exit(0);
  }

  for (; *args; args++) {
    if (anyeq(*args, "-h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (npos == 2 && ++npos) {
      nonce = *args;
    } else if (npos == 1 && ++npos) {
      sscanf(*args, "%lu", &lu);
      counter = lu;
    } else if (npos == 0 && ++npos) {
      key = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (npos != 3) {
    fprintf(stderr, "Missing arguments!\n");
    exit(1);
  }

  parse_hex2buf(keyb, 32, "key", key);
  parse_hex2buf(nonceb, 12, "nonce", nonce);

  slowcrypt_chacha20_init(state, keyb, counter, nonceb);
  slowcrypt_chacha20_run(state, &state[1], 20);
  slowcrypt_chacha20_serialize(buf, state);

  for (nb = 0; nb < 64; nb++)
    printf("%02x", buf[nb]);
  printf("\n");
}

static void run_chacha20_crypt(char** args)
{
  static char const help[] =
      "chacha20 [--pad <padding>] [--init-counter <n>] [--full-chunks] <key> "
      "<nonce> <file>\n"
      "\n"
      "Run the ChaCha20 en-/de- cryption algorithm on the given file, or "
      "stdin, and output the result to stdout\n"
      "\n"
      "Defaults to padding with zeros, but can be overwritten with --pad <n>\n"
      ""
      "Outputs only the number of input bytes from the last block. This "
      "behaviour can be changed by passing --full-chunks\n";
  char const *key, *nonce, *fpath = "-";
  unsigned int npos = 0;
  unsigned int nb, i;
  unsigned long ul;
  uint8_t pad = 0;
  int full_chunks = 0;
  uint32_t counter = 1;
  slowcrypt_chacha20 state[2];
  uint8_t buf[64];
  uint8_t keyb[32];
  uint8_t nonceb[12];
  FILE* fp;

  if (!*args) {
    printf("%s", help);
    exit(0);
  }

  for (; *args; args++) {
    if (anyeq(*args, "-full-chunk", "--full-chunk", "-full-chunks",
              "--full-chunks")) {
      full_chunks = 1;
    } else if (anyeq(*args, "-pad", "--pad", "--padding") && args[1]) {
      args++;
      pad = (uint8_t)atoi(*args);
    } else if (anyeq(*args, "-init-counter", "-initial-counter",
                     "--initial-counter", "--init-counter") &&
               args[1]) {
      args++;
      sscanf(*args, "%lu", &ul);
      counter = ul;
    } else if (anyeq(*args, "-h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (npos == 2 && ++npos) {
      fpath = *args;
    } else if (npos == 1 && ++npos) {
      nonce = *args;
    } else if (npos == 0 && ++npos) {
      key = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (npos < 2) {
    fprintf(stderr, "Missing arguments!\n");
    exit(1);
  }

  parse_hex2buf(keyb, 32, "key", key);
  parse_hex2buf(nonceb, 12, "nonce", nonce);

  fp = file_open(fpath);

  for (; (nb = file_read_chunk(fp, buf, 64)); counter++) {
    for (i = nb; i < 64; i++)
      buf[i] = pad;
    slowcrypt_chacha20_block(state, keyb, counter, nonceb, buf);
    if (full_chunks)
      nb = 64;
    fwrite(buf, 1, nb, stdout);
  }

  file_close(fp);
}

static void run_chacha20_csprng_manual(char** args)
{
  static char const help[] =
      "chacha20-csprng-manual [--limit <num bytes>] [--init-counter <n>] "
      "[--key "
      "<key>] "
      "[--nonce <nonce>] \n"
      "\n"
      "Run the ChaCha20 function repeatedly, with incrementing counter, "
      "(starting at the given initial counter, defaulting to 1),"
      "writing the output to stdout.\n"
      "\n"
      "If no limit (in number of bytes) is given, will repeat forever.\n"
      "\n"
      "Both key and nonce will be generated randomly (using the highest "
      "entropy random source available), unless overwritten\n";
  char const* key = 0;
  char const* nonce = 0;
  unsigned long ul;
  unsigned long limit = 0;
  unsigned long nb, nwrb;
  uint32_t counter = 1;
  slowcrypt_chacha20 state[2];
  uint8_t buf[64];
  uint8_t keyb[32];
  uint8_t nonceb[12];

  for (; *args; args++) {
    if (anyeq(*args, "-limit", "--limit") && args[1]) {
      args++;
      sscanf(*args, "%lu", &ul);
      limit = ul;
    } else if (anyeq(*args, "-init-counter", "-initial-counter",
                     "--initial-counter", "--init-counter") &&
               args[1]) {
      args++;
      sscanf(*args, "%lu", &ul);
      counter = ul;
    } else if (anyeq(*args, "-h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (anyeq(*args, "-key", "--key")) {
      args++;
      key = *args;
    } else if (anyeq(*args, "-nonce", "--nonce")) {
      args++;
      nonce = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (key) {
    parse_hex2buf(keyb, 32, "key", key);
  } else {
    slowcrypt_systemrand(keyb, 32, 0);
  }

  if (nonce) {
    parse_hex2buf(nonceb, 12, "nonce", nonce);
  } else {
    slowcrypt_systemrand(keyb, 12, 0);
  }

  if (!limit) {
    for (;; counter++) {
      slowcrypt_chacha20_init(state, keyb, counter, nonceb);
      slowcrypt_chacha20_run(state, &state[1], 20);
      slowcrypt_chacha20_serialize(buf, state);
      fwrite(buf, 1, 64, stdout);
    }
  } else {
    for (nb = 0; nb < limit; (nb += 64, counter++)) {
      nwrb = limit - nb;
      if (nwrb > 64)
        nwrb = 64;
      slowcrypt_chacha20_init(state, keyb, counter, nonceb);
      slowcrypt_chacha20_run(state, &state[1], 20);
      slowcrypt_chacha20_serialize(buf, state);
      fwrite(buf, 1, nwrb, stdout);
    }
  }

  slowcrypt_chacha20_deinit(&state[0]);
  slowcrypt_chacha20_deinit(&state[1]);
}

static void run_poly1305(char** args)
{
  static char const help[] =
      "poly1305 [--key] <hex-key> [file]\n"
      "\n"
      "Run the Poly1305 one-time authenticator on the data from the given file "
      "or stdin\n";
  char const* key = 0;
  char const* fpath = "-";
  FILE* fp;
  unsigned int npos = 0;
  uint8_t keybuf[32];
  uint8_t chunk[16];
  slowcrypt_poly1305 poly1305;
  unsigned int nb;

  if (!*args) {
    printf("%s", help);
    exit(0);
  }

  for (; *args; args++) {
    if (!key && anyeq(*args, "-k", "-key", "--key") && args[1]) {
      args++;
      key = *args;
    } else if (anyeq(*args, "-h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (npos == 1 && ++npos) {
      fpath = *args;
    } else if (npos == 0 && ++npos && !key) {
      key = *args;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (!key) {
    fprintf(stderr, "Missing argument: [--key] <hex-key>");
    exit(1);
  }

  fp = file_open(fpath);

  parse_hex2buf(keybuf, 32, "key", key);
  slowcrypt_poly1305_init(&poly1305, keybuf);

  while ((nb = file_read_chunk(fp, chunk, 16))) {
    slowcrypt_poly1305_next_block(&poly1305, chunk, nb);
  }
  slowcrypt_poly1305_finish(&poly1305, chunk);

  for (nb = 0; nb < 16; nb++)
    printf("%02x", chunk[nb]);
  printf("\n");

  file_close(fp);
}

static void distribute(uint8_t* out,
                       unsigned int outlen,
                       uint8_t const* in,
                       unsigned int inlen)
{
  unsigned oidx, iidx;
  fprintf(stderr, "seeding RNGs not yet implemented!\n");
  exit(1);
  /* TODO */
}

static void run_chacha20_csprng(char** args)
{
  unsigned long limit, nb, nwrb, seedlen;
  char* seed;
  char const description[] =
      "Run the ChaCha20 function repeatedly with incrementing counters, to "
      "produce random data\n";
  uint8_t keynonceb[44];
  unsigned long counter = 1;
  slowcrypt_chacha20 state[2];
  uint8_t buf[64];

  parse_rng_args(&limit, &seed, "chacha20-csprng", description, args);
  if (seed) {
    seedlen = strlen(seed);
    distribute(keynonceb, 44, (uint8_t const*)seed, seedlen);
  } else {
    slowcrypt_systemrand(keynonceb, 44, 0);
  }

  if (!limit) {
    for (;; counter++) {
      slowcrypt_chacha20_init(state, &keynonceb[0], counter, &keynonceb[32]);
      slowcrypt_chacha20_run(state, &state[1], 20);
      slowcrypt_chacha20_serialize(buf, state);
      fwrite(buf, 1, 64, stdout);
    }
  } else {
    for (nb = 0; nb < limit; (nb += 64, counter++)) {
      nwrb = limit - nb;
      if (nwrb > 64)
        nwrb = 64;
      slowcrypt_chacha20_init(state, &keynonceb[0], counter, &keynonceb[32]);
      slowcrypt_chacha20_run(state, &state[1], 20);
      slowcrypt_chacha20_serialize(buf, state);
      fwrite(buf, 1, nwrb, stdout);
    }
  }

  slowcrypt_chacha20_deinit(&state[0]);
  slowcrypt_chacha20_deinit(&state[1]);
}

static uint16_t prng_step(uint16_t x)
{
  x ^= x << 1;
  x ^= x >> 1;
  x ^= x << 3;  // 5 shifts, cycle of 32767
  return x;
}

static void prng_buf(uint16_t* buf, unsigned long buflen, uint16_t* acc)
{
  for (; buflen; --buflen, ++buf) {
    *acc = prng_step(*acc);
    *buf = *acc;
  }
}

static void run_prng(char** args)
{
  unsigned long limit, nb, nwrb, seedlen;
  char* seed;
  char const description[] =
      "Run a weak implementation-dependent (non cryptographically secure) "
      "PRNG\n";
  uint16_t acc;
  uint16_t buf[32];

  parse_rng_args(&limit, &seed, "prng", description, args);
  if (seed) {
    seedlen = strlen(seed);
    distribute((uint8_t*)&acc, sizeof(acc), (uint8_t const*)seed, seedlen);
  } else {
    slowcrypt_systemrand((uint8_t*)&acc, sizeof(acc), 0);
  }

  if (!limit) {
    for (;;) {
      prng_buf(buf, 32, &acc);
      fwrite(buf, 1, 64, stdout);
    }
  } else {
    for (nb = 0; nb < limit; nb += 64) {
      nwrb = limit - nb;
      if (nwrb > 64)
        nwrb = 64;
      prng_buf(buf, 32, &acc);
      fwrite(buf, 1, nwrb, stdout);
    }
  }
}

static void run_entropy(char** args)
{
  static char const help[] =
      "entropy [--limit <num bytes>] [--bail-if-insecure] "
      "[--insecure-non-blocking]\n\nUses the operating system's RNG to "
      "produce high-entropy random data\n";

  unsigned long limit = 0;
  unsigned int nb, nwrb;
  static uint8_t buf[256];
  slowcrypt_systemrand_flags flags = 0;

  for (; *args; args++) {
    if (anyeq(*args, "-h", "--h", "-help", "--help")) {
      printf("%s", help);
      exit(0);
    } else if (anyeq(*args, "-limit", "--limit", "-n")) {
      args++;
      sscanf(*args, "%lu", &limit);
    } else if (anyeq(*args, "-bail-if-insecure", "--bail-if-insecure")) {
      flags |= SLOWCRYPT_SYSTEMRAND__BAIL_IF_INSECURE;
    } else if (anyeq(*args, "-insecure-non-blocking",
                     "--insecure-non-blocking")) {
      flags |= SLOWCRYPT_SYSTEMRAND__INSECURE_NON_BLOCKING;
    } else {
      fprintf(stderr, "Unexpected argument: %s\n", *args);
      exit(1);
    }
  }

  if (!limit) {
    for (;;) {
      if (slowcrypt_systemrand(buf, 256, flags))
        exit(1);
      fwrite(buf, 1, 256, stdout);
    }
  } else {
    for (nb = 0; nb < limit; nb += 256) {
      nwrb = limit - nb;
      if (nwrb > 256)
        nwrb = 256;
      if (slowcrypt_systemrand(buf, nwrb, flags))
        exit(1);
      fwrite(buf, 1, nwrb, stdout);
    }
  }
}

static struct algo bytes2scalar[] = {{"poly1305", run_poly1305},
                                     {"chacha20-core", run_chacha20_core},
                                     {"kchacha", run_kchacha},
                                     {"balloon-kchacha", run_balloon_kchacha},
                                     {0, 0}};

static struct algo bytes2bytes[] = {{"chacha20", run_chacha20_crypt}, {0, 0}};

static struct algo scalar2bytes[] = {
    {"entropy", run_entropy},
    {"chacha20-csprng", run_chacha20_csprng},
    {"chacha20-csprng-manual", run_chacha20_csprng_manual},
    {"prng", run_prng},
    {0, 0}};

int main(int argc, char** argv)
{
  struct algo* a;
  (void)argc;

  /* used by systemrand if no better rng available */
  srand((unsigned int)time(0));

  argv++;
  if (!*argv || anyeq(*argv, "-h", "-help", "--help")) {
    printf("bytes -> scalar\n");
    for (a = bytes2scalar; a->name; a++)
      printf("  %s\n", a->name);
    printf("\nbytes -> bytes\n");
    for (a = bytes2bytes; a->name; a++)
      printf("  %s\n", a->name);
    printf("\nscalar -> bytes\n");
    for (a = scalar2bytes; a->name; a++)
      printf("  %s\n", a->name);
    return 0;
  }

  for (a = bytes2scalar; a->name; a++) {
    if (!strcmp(a->name, *argv)) {
      a->run(argv + 1);
      return 0;
    }
  }

  for (a = bytes2bytes; a->name; a++) {
    if (!strcmp(a->name, *argv)) {
      a->run(argv + 1);
      return 0;
    }
  }

  for (a = scalar2bytes; a->name; a++) {
    if (!strcmp(a->name, *argv)) {
      a->run(argv + 1);
      return 0;
    }
  }

  fprintf(stderr, "Unknown algorithm %s\n", *argv);
  return 1;
}

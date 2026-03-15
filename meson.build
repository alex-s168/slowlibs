project('slowlibs', 'c', 'cpp',
  version: '1.0.0-pre.1')

install_headers(
  './include/slowlibs/chacha20.h',
  './include/slowlibs/csv.h',
  './include/slowlibs/poly1305.h',
  './include/slowlibs/fixed_bigint.h',
  './include/slowlibs/util.h',
  './include/slowlibs/slowarr.h',
  './include/slowlibs/slowgraph.h',
  './include/slowlibs/systemrand.h',
  './include/slowlibs/cbor.h',
  subdir: 'slowlibs')

slowlibs_headeronly_dep = declare_dependency(
  include_directories: 'include')
meson.override_dependency('slowlibs-headeronly', slowlibs_headeronly_dep)

sha3_gen_rc = custom_target('sha3_gen_rc',
  command: executable('sha3_gen_rc', 'src/slowcrypt/sha3_gen_rc.c'),
  capture: true,
  output: 'sha3_gen_rc.h')

libslowlibs = static_library('slowlibs',
  'src/io.c',
  'src/util.c',
  'src/include_impl.c',
  'src/slowcrypt/sha3.c',
  'src/slowcrypt/systemrand.c',
  'src/slowcrypt/chacha20.c',
  'src/slowcrypt/balloon_kchacha.c',
  sha3_gen_rc,
  install: true,
  dependencies: [slowlibs_headeronly_dep])

slowlibs_dep = declare_dependency(
  include_directories: 'include',
  link_with: libslowlibs)
meson.override_dependency('slowlibs', slowlibs_dep)


executable('slowcrypt',
  './src/slowcrypt/cli-slowcrypt.c',
  dependencies: [slowlibs_dep],
  install: true)

executable('sgraph-adj',
  './src/slowgraph/cli-sgraph-adj.c',
  dependencies: [slowlibs_headeronly_dep],
  install: true)



test('chacha20-block_test_vector', executable('chacha20-block_test_vector',
  './tests/chacha20/block_test_vector.c',
  dependencies: [slowlibs_dep]))

test('chacha20-keygen_test_vector', executable('chacha20-keygen_test_vector',
  './tests/chacha20/keygen_test_vector.c',
  dependencies: [slowlibs_dep]))

test('chacha20-h_test_vector', executable('chacha20-h_test_vector',
  './tests/chacha20/hchacha20.c',
  dependencies: [slowlibs_dep]))

test('chacha20-k_test_vector', executable('chacha20-k_test_vector',
  './tests/chacha20/kchacha.c',
  dependencies: [slowlibs_dep]))
test('chacha20-unpaddedk_test_vector', executable('chacha20-unpaddedk_test_vector',
  './tests/chacha20/kchacha_unpadded.c',
  dependencies: [slowlibs_dep]))

test('chacha20-balloon', executable('chacha20-balloon',
  './tests/chacha20/balloon.c',
  dependencies: [slowlibs_dep]))

test('chacha20-balloon-unpadded', executable('chacha20-balloon-unpadded',
  './tests/chacha20/balloon_unpadded.c',
  dependencies: [slowlibs_dep]))
  
test('poly1305-test_vector_bitint', executable('poly1305-test_vector_bitint',
  './tests/poly1305/test_vector_bitint.c',
  dependencies: [slowlibs_headeronly_dep]))

test('poly1305-test_vector_fbig', executable('poly1305-test_vector_fbig',
  './tests/poly1305/test_vector_fbig.c',
  dependencies: [slowlibs_headeronly_dep]))

test('slowarr-nostd.1', executable('slowarr-nostd.1',
  './tests/slowarr/nostd1.c',
  dependencies: [slowlibs_headeronly_dep]))

test('slowarr-std.1', executable('slowarr-std.1',
  './tests/slowarr/std1.c',
  dependencies: [slowlibs_headeronly_dep]))

test('slowarr-std.1-cxx', executable('slowarr-std.1-cxx',
  './tests/slowarr/std1.cxx',
  dependencies: [slowlibs_headeronly_dep]))

test('utils-test', executable('utils-test',
  './tests/util/memrevcpy.c',
  dependencies: [slowlibs_dep]))

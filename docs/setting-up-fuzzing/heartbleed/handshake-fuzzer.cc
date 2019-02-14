// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Original version written by Kostya Serebryany.
//

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string>

#ifdef __cpp_lib_filesystem
#include <filesystem>
static std::filesystem::path filepath;
#else
#include <experimental/filesystem>
static std::experimental::filesystem::path filepath;
#endif

static SSL_CTX *sctx;

class  Environment {
 public:
  Environment() {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    assert(sctx = SSL_CTX_new(TLSv1_method()));
    filepath.replace_filename("server.pem");
    assert(SSL_CTX_use_certificate_file(sctx, filepath.c_str(),
                                        SSL_FILETYPE_PEM));
    filepath.replace_filename("server.key");
    assert(SSL_CTX_use_PrivateKey_file(sctx, filepath.c_str(),
                                       SSL_FILETYPE_PEM));
  }
};

extern "C" int LLVMFuzzerInitialize(const int* argc, char*** argv) {
  filepath = std::string(*argv[0]);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static Environment env;
  SSL *server = SSL_new(sctx);
  BIO *sinbio = BIO_new(BIO_s_mem());
  BIO *soutbio = BIO_new(BIO_s_mem());
  SSL_set_bio(server, sinbio, soutbio);
  SSL_set_accept_state(server);
  BIO_write(sinbio, Data, Size);
  SSL_do_handshake(server);
  SSL_free(server);
  return 0;
}

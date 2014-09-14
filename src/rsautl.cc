#include <node.h>
#include <node_crypto.h>
#include <nan.h>

#include <openssl/rsa.h>

#define LOG(msg) printf("%s\n", msg);
// #define LOG(msg) ;


#define REQ_BUF_ARG(I, VAR)                                                   \
  if (args.Length() <= (I) || !Buffer::HasInstance(args[I]))                  \
    return NanThrowTypeError("Argument " #I " must be a buffer");             \
  Local<Object> _ ## VAR = args[I]->ToObject();                               \
  char *VAR = Buffer::Data(_ ## VAR);                                         \
  size_t VAR ## _len = Buffer::Length(_ ## VAR);

using namespace v8;
using namespace node;

typedef enum {
  kRsaOk,
  kRsaKey
} Error;
typedef RSA* rsa_read_bio_cb(BIO *bp, RSA **rsa, pem_password_cb *cb, void *u);
typedef int rsa_type_action_cb(int flen,
                               const unsigned char *from,
                               unsigned char *to,
                               RSA *rsa,
                               int padding);

static void CheckThrow(Error error) {
  NanScope();

  switch (error) {
    case kRsaKey:
      return NanThrowError("Failed.");
    default:
      return;
  }
}

static int CryptoPemCallback(char *buf, int size, int rwflag, void *u) {
  if (u) {
    size_t buflen = static_cast<size_t>(size);
    size_t len = strlen(static_cast<const char*>(u));
    len = len > buflen ? buflen : len;
    memcpy(buf, u, len);
    return len;
  }
  return 0;
}

Error Generic(rsa_read_bio_cb *read_key_cb,
              rsa_type_action_cb *transform_cb,
              const char* in,
              int in_len,
              const char* key_pem,
              int key_pem_len,
              const char* passphrase,
              char** out,
              size_t *out_len,
              int pad) {
  BIO* bp = NULL;
  RSA* rsa = NULL;
  bool fatal = true;

  bp = BIO_new(BIO_s_mem());
  if (bp == NULL)
    goto exit;

  if (!BIO_write(bp, key_pem, key_pem_len))
    goto exit;

  LOG("Reading key.")

  rsa = read_key_cb(bp,
                    NULL,
                    CryptoPemCallback,
                    const_cast<char*>(passphrase));
  if (rsa == NULL)
    goto exit;

  LOG("Key read.")
  LOG("Tweaking data.")

  *out_len = transform_cb(in_len,
                         (unsigned char *) in,
                         (unsigned char *) *out,
                         rsa,
                         pad);
  if (*out_len > 0)
    fatal = false;
  LOG("Data tweaked.")

 exit:
  if (rsa != NULL)
    RSA_free(rsa);
  if (bp != NULL)
    BIO_free_all(bp);

//   printf("Test %128s\n", out);
  LOG("Freed")
  printf("Fucking %i\n", *out_len);
  printf("Fatal? %i\n", fatal);

  if (fatal)
    return kRsaKey;

  return kRsaOk;
}

NAN_METHOD(Decrypt) {
  NanScope();
  LOG("Beginning Decrypt")
}
NAN_METHOD(Encrypt) {
  NanScope();
  LOG("Beginning Encrypt")
}
NAN_METHOD(Sign) {
  NanScope();
  LOG("Beginning Sign")

  REQ_BUF_ARG(0, in)
  REQ_BUF_ARG(1, key_pem)

  LOG("Read buffers")

  String::Utf8Value passphrase(args[2]);

  LOG("passphrase?")

  size_t out_len = 8192;
  char *out;
  out = new char[out_len];
  int pad = RSA_PKCS1_PADDING;

  Error err = Generic(PEM_read_bio_RSAPrivateKey,
                      RSA_private_encrypt,
                      in,
                      in_len,
                      key_pem,
                      key_pem_len,
                      args.Length() >= 3 && !args[2]->IsNull() ? *passphrase : NULL,
                      &out,
                      &out_len,
                      pad);
//   if (err != kRsaOk) {
// //     delete[] out;
//     out_len = 0;
//     return CheckThrow(err);
//   }
  LOG("A")

//   printf("Fucking %i", out_len);
//   NanReturnValue(NanNew<Number>(out_len));
  Local<Value> rc = NanNewBufferHandle(out, out_len);

  delete[] out;
  LOG("Post delete")
  NanReturnValue(rc);

}
NAN_METHOD(Verify) {
  NanScope();
  LOG("Beginning Verify")
}

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "decrypt", Decrypt);
  NODE_SET_METHOD(exports, "encrypt", Encrypt);
  NODE_SET_METHOD(exports, "sign",    Sign);
  NODE_SET_METHOD(exports, "verify",  Verify);
}

NODE_MODULE(rsautl, init)

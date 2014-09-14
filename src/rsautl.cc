#include <node.h>
#include <nan.h>

#include "compat.h"

// #define LOG(msg) printf("%s\n", msg);
#define LOG(msg) ;


#define REQ_BUF_ARG(I, VAR)                                                   \
  if (args.Length() <= (I) || !Buffer::HasInstance(args[I]))                  \
    return NanThrowTypeError("Argument " #I " must be a buffer");             \
  Local<Object> _ ## VAR = args[I]->ToObject();                               \
  char *VAR = Buffer::Data(_ ## VAR);                                         \
  size_t VAR ## _len = Buffer::Length(_ ## VAR); 

#define KEY_ARGS_private key_pem, key_pem_len, NULL
#define KEY_ARGS_public  key_pem, key_pem_len

#define RSAUTL_METHOD(NAME, KEY, OP)                                          \
NAN_METHOD(NAME) {                                                            \
  NanScope();                                                                 \
  LOG("Beginning " #NAME)                                                     \
                                                                              \
  int out_len = 0;                                                            \
  char *out = NULL;                                                           \
  int pad = RSA_PKCS1_PADDING;                                                \
  bool fatal = true;                                                          \
                                                                              \
  REQ_BUF_ARG(0, in)                                                          \
  REQ_BUF_ARG(1, key_pem)                                                     \
                                                                              \
  RSA* rsa = rsa_ ## KEY ## _key(KEY_ARGS_ ## KEY);                           \
  if (rsa == NULL)                                                            \
    goto exit;                                                                \
                                                                              \
  out_len = RSA_size(rsa);                                                    \
  out = new char[out_len];                                                    \
  out_len = RSA_ ## KEY ## _ ## OP(in_len,                                    \
                                   (unsigned char *) in,                      \
                                   (unsigned char *) out,                     \
                                   rsa,                                       \
                                   pad);                                      \
  if (out_len > 0)                                                            \
    fatal = false;                                                            \
                                                                              \
 exit:                                                                        \
  if (rsa != NULL)                                                            \
    RSA_free(rsa);                                                            \
                                                                              \
  if (fatal)                                                                  \
    return NanThrowError("RSA_" #KEY "_" #OP " failed");                      \
                                                                              \
  Local<Value> rc = NanNewBufferHandle(out, out_len);                         \
  NanReturnValue(rc);                                                         \
}

using namespace v8;
using namespace node;

RSAUTL_METHOD(Decrypt, private, decrypt)
RSAUTL_METHOD(Encrypt, public,  encrypt)
RSAUTL_METHOD(Sign,    private, encrypt)
RSAUTL_METHOD(Verify,  public,  decrypt)

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "decrypt", Decrypt);
  NODE_SET_METHOD(exports, "encrypt", Encrypt);
  NODE_SET_METHOD(exports, "sign",    Sign);
  NODE_SET_METHOD(exports, "verify",  Verify);
}

NODE_MODULE(rsautl, init)

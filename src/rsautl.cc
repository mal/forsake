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

using namespace v8;
using namespace node;

NAN_METHOD(Decrypt) {
  NanScope();
  LOG("Beginning Decrypt")

  int out_len = 0;
  char *out = NULL;
  int pad = RSA_PKCS1_PADDING;
  bool fatal = true;

  REQ_BUF_ARG(0, in)
  REQ_BUF_ARG(1, key_pem)

  RSA* rsa = rsa_private_key(key_pem, key_pem_len, NULL);
  if (rsa == NULL)
    goto exit;

  out_len = RSA_size(rsa);
  out = new char[out_len];
  out_len = RSA_private_decrypt(in_len,
                                (unsigned char *) in,
                                (unsigned char *) out,
                                rsa,
                                pad);
  if (out_len > 0)
    fatal = false;

 exit:
  if (rsa != NULL)
    RSA_free(rsa);

  if (fatal)
    return NanThrowError("RSA_private_decrypt failed");

  Local<Value> rc = NanNewBufferHandle(out, out_len);
  NanReturnValue(rc);
}

NAN_METHOD(Encrypt) {
  NanScope();
  LOG("Beginning Encrypt")

  int out_len = 0;
  char *out = NULL;
  int pad = RSA_PKCS1_PADDING;
  bool fatal = true;

  REQ_BUF_ARG(0, in)
  REQ_BUF_ARG(1, key_pem)

  RSA* rsa = rsa_public_key(key_pem, key_pem_len);
  if (rsa == NULL)
    goto exit;

  out_len = RSA_size(rsa);
  out = new char[out_len];
  out_len = RSA_public_encrypt(in_len,
                               (unsigned char *) in,
                               (unsigned char *) out,
                               rsa,
                               pad);
  if (out_len > 0)
    fatal = false;

 exit:
  if (rsa != NULL)
    RSA_free(rsa);

  if (fatal)
    return NanThrowError("RSA_public_encrypt failed");

  Local<Value> rc = NanNewBufferHandle(out, out_len);
  NanReturnValue(rc);
}

NAN_METHOD(Sign) {
  NanScope();
  LOG("Beginning Sign")

  int out_len = 0;
  char *out = NULL;
  int pad = RSA_PKCS1_PADDING;
  bool fatal = true;

  REQ_BUF_ARG(0, in)
  REQ_BUF_ARG(1, key_pem)

  RSA* rsa = rsa_private_key(key_pem, key_pem_len, NULL);
  if (rsa == NULL)
    goto exit;

  out_len = RSA_size(rsa);
  out = new char[out_len];
  out_len = RSA_private_encrypt(in_len,
                                (unsigned char *) in,
                                (unsigned char *) out,
                                rsa,
                                pad);
  if (out_len > 0)
    fatal = false;

 exit:
  if (rsa != NULL)
    RSA_free(rsa);

  if (fatal)
    return NanThrowError("RSA_private_encrypt failed");

  Local<Value> rc = NanNewBufferHandle(out, out_len);
  NanReturnValue(rc);
}

NAN_METHOD(Verify) {
  NanScope();
  LOG("Beginning Verify")

  int out_len = 0;
  char *out = NULL;
  int pad = RSA_PKCS1_PADDING;
  bool fatal = true;

  REQ_BUF_ARG(0, in)
  REQ_BUF_ARG(1, key_pem)

  RSA* rsa = rsa_public_key(key_pem, key_pem_len);
  if (rsa == NULL)
    goto exit;

  out_len = RSA_size(rsa);
  out = new char[out_len];
  out_len = RSA_public_decrypt(in_len,
                               (unsigned char *) in,
                               (unsigned char *) out,
                               rsa,
                               pad);
  if (out_len > 0)
    fatal = false;

 exit:
  if (rsa != NULL)
    RSA_free(rsa);

  if (fatal)
    return NanThrowError("RSA_public_decrypt failed");

  Local<Value> rc = NanNewBufferHandle(out, out_len);
  NanReturnValue(rc);
}

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "decrypt", Decrypt);
  NODE_SET_METHOD(exports, "encrypt", Encrypt);
  NODE_SET_METHOD(exports, "sign",    Sign);
  NODE_SET_METHOD(exports, "verify",  Verify);
}

NODE_MODULE(rsautl, init)

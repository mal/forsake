#ifndef SRC_NODE_RSAUTL_H_
#define SRC_NODE_RSAUTL_H_

#include <node.h>
#include <nan.h>

#include <openssl/rsa.h>

using namespace v8;

class RsaUtl : public node::ObjectWrap {
 public:
  static void Init(Handle<Object> exports);

  static NAN_METHOD(Sign)
  static NAN_METHOD(Verify)
  static NAN_METHOD(Encrypt)
  static NAN_METHOD(Decrypt)
}

#endif // SRC_NODE_RSAUTL_H_

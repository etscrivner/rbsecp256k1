#include <ruby.h>
#include <secp256k1.h>

void Init_rbsecp256k1()
{
  VALUE secp256k1_module = rb_define_module("Secp256k1");
}

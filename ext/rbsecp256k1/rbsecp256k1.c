// rbsecp256k1.c - Ruby VM interfaces for library.
//
// Description:
// This library provides a low-level and high-performance Ruby wrapper around
// libsecp256k1. It includes functions for generating key pairs, signing data,
// and verifying signatures using the library.
//
// Dependencies:
// libsecp256k1
// openssl
#include <ruby.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <secp256k1.h>

// High-level design:
//
// The Ruby wrapper is divided into the following hierarchical organization:
//
// Secp256k1 (Top-level module)
// +- Context
// +- PublicKey
// +- PrivateKey
// +- Signature
//
// The Context object contains most of the methods that invoke libsecp256k1.
// The PublicKey, PrivateKey, and Signature objects act as data objects passed
// to various methods on the Context object. A new context is required for any
// interaction at all with the library.

//
// The section below contains purely internal methods used exclusively by the
// C internals of the library.
// 

/**
 * Macro: SUCCESS
 * 
 * Determines whether or not the given function result was a success.
 */
#define SUCCESS(x) ((x) == RESULT_SUCCESS)

/* Result type for internally defined functions */
typedef enum ResultT_dummy {
  RESULT_SUCCESS,
  RESULT_FAILURE
} ResultT;

/**
 * Generate a series of cryptographically secure random bytes using OpenSSL.
 *
 * \param out_bytes Desired number of bytes will be written here.
 * \param in_size Number of bytes of random data to be generated.
 * \return RESULT_SUCCESS if the bytes were generated successfully,
 *   RESULT_FAILURE otherwise.
 */
ResultT GenerateRandomBytes(unsigned char *out_bytes, size_t in_size)
{
  // OpenSSL RNG has not been seeded with enough data and is therefore
  // not usable.
  if (RAND_status() == 0)
  {
    
    return RESULT_FAILURE;
  }

  // Attempt to generate random bytes using the OpenSSL RNG
  if (RAND_bytes(out_bytes, in_size) != 1)
  {
    // TODO: Improve the error-handling here
    return RESULT_FAILURE;
  }

  return RESULT_SUCCESS;
}

/**
 * Secp256k1.generate_private_key_bytes
 *
 * Generate cryptographically secure 32 byte private key data.
 */
static VALUE
Secp256k1_generate_private_key_bytes(VALUE self)
{
  unsigned char private_key_bytes[32];

  GenerateRandomBytes(private_key_bytes, 32);

  return rb_str_new((char*)private_key_bytes, 32);
}

//
// Secp256k1::PrivateKey class interface
//

/* PrivateKey object internal data structure */
typedef struct PrivateKey_dummy {
  unsigned char data[32]; // Bytes comprising the private key data
} PrivateKey;

/* Allocate space for new private key internal data */
static VALUE
PrivateKey_alloc(VALUE klass)
{
  VALUE new_instance;
  PrivateKey *private_key;

  new_instance = Data_Make_Struct(
    klass, PrivateKey, NULL, free, private_key
  );
  memset(private_key->data, 0, 32);

  return new_instance;
}

/* PrivateKey#initialize */
static VALUE
PrivateKey_initialize(VALUE self, VALUE bytes)
{
  PrivateKey *private_key;

  Check_Type(bytes, T_STRING);

  if (RSTRING_LEN(bytes) != 32)
  {
    rb_raise(rb_eTypeError, "bytes must exactly 32 bytes in length");
    return self;
  }

  Data_Get_Struct(self, PrivateKey, private_key);
  memcpy(private_key->data, RSTRING_PTR(bytes), 32);

  return self;
}

//
// Secp256k1::Context class interface
//

/* Context object internal data structure */
typedef struct Context_dummy {
  secp256k1_context *ctx; // Context used by libsecp256k1 library
} Context;

/* Deallocate a context when it is garbage collected */
static void
Context_free(void* in_context)
{
  Context *context = (Context*)in_context;

  secp256k1_context_destroy(context->ctx);
  free(context);
}

/* Allocate a new context object */
static VALUE
Context_alloc(VALUE klass)
{
  VALUE new_instance;
  Context *context;

  new_instance = Data_Make_Struct(
    klass, Context, NULL, Context_free, context
  );
  context->ctx = NULL;

  return new_instance;
}

/* Context#initialize */
static VALUE
Context_initialize(VALUE self)
{
  Context *context;

  Data_Get_Struct(self, Context, context);

  // TODO: Handle structure allocation failure

  // Initialize the libsecp256k1 context data
  context->ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
  );

  // TODO: Handle context creation failure

  return self;
}

//
// Secp256k1::PublicKey class interface
//

/* PublicKey internal data structure */
typedef struct PublicKey_dummy {
  secp256k1_pubkey pubkey;
} PublicKey;

static VALUE
PublicKey_alloc(VALUE klass)
{
  VALUE new_instance;
  PublicKey *public_key;

  new_instance = Data_Make_Struct(
    klass, PublicKey, NULL, free, public_key
  );

  return new_instance;
}

static VALUE
PublicKey_initialize(VALUE self, VALUE in_context, VALUE in_private_key)
{
  Context *context;
  PublicKey *public_key;
  PrivateKey *private_key;

  Data_Get_Struct(self, PublicKey, public_key);
  Data_Get_Struct(in_context, Context, context);
  Data_Get_Struct(in_private_key, PrivateKey, private_key);

  if (secp256k1_ec_pubkey_create(context->ctx,
                                 &(public_key->pubkey),
                                 private_key->data) == 0)
  {
    rb_raise(rb_eTypeError, "Invalid private key data");
    return self;
  }

  return self;
}

//
// Library initialization
//

void Init_rbsecp256k1()
{
  // Secp256k1
  VALUE Secp256k1_module = rb_define_module("Secp256k1");
  rb_define_singleton_method(
    Secp256k1_module, "generate_private_key_bytes", Secp256k1_generate_private_key_bytes, 0
  );

  // Secp256k1::Context
  VALUE Secp256k1_Context_class = rb_define_class_under(
    Secp256k1_module, "Context", rb_cObject
  );
  rb_define_alloc_func(Secp256k1_Context_class, Context_alloc);
  rb_define_method(Secp256k1_Context_class,
                   "initialize", Context_initialize, 0);

  // Secp256k1::PrivateKey
  VALUE Secp256k1_PrivateKey_class = rb_define_class_under(
    Secp256k1_module, "PrivateKey", rb_cObject
  );
  rb_define_alloc_func(Secp256k1_PrivateKey_class, PrivateKey_alloc);
  rb_define_method(Secp256k1_PrivateKey_class, "initialize", PrivateKey_initialize, 1);

  // Secp256k1::PublicKey
  VALUE Secp256k1_PublicKey_class = rb_define_class_under(
    Secp256k1_module, "PublicKey", rb_cObject
  );
  rb_define_alloc_func(Secp256k1_PublicKey_class, PublicKey_alloc);
  rb_define_method(Secp256k1_PublicKey_class, "initialize", PublicKey_initialize, 2);
}

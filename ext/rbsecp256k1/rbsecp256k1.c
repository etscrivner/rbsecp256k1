// rbsecp256k1.c - Ruby VM interfaces for library.
//
// Description:
// This library provides a low-level and high-performance Ruby wrapper around
// libsecp256k1. It includes functions for generating key pairs, signing data,
// and verifying signatures using the library.
//
// Dependencies:
// * libsecp256k1
// * openssl
#include <ruby.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <secp256k1.h>

// High-level design:
//
// The Ruby wrapper is divided into the following hierarchical organization:
//
// +- Secp256k1 (Top-level module)
// |--  Context
// |--  KeyPair
// |--  PublicKey
// |--  PrivateKey
// |--  Signature
//
// The Context class contains most of the methods that invoke libsecp256k1.
// The KayPair, PublicKey, PrivateKey, and Signature objects act as data
// objects and are passed to various methods. Contexts are thread safe and can
// be used across applications. Context initialization is expensive so it is
// recommended that a single context be initialized and used throughout an
// application when possible.

//
// The section below contains purely internal methods used exclusively by the
// C internals of the library.
//

// Globally define our module and its associated classes so we can instantiate
// objects from anywhere. The use of global variables seems to be inline with
// how the Ruby project builds its own extension gems.
static VALUE Secp256k1_module;
static VALUE Secp256k1_Context_class;
static VALUE Secp256k1_KeyPair_class;
static VALUE Secp256k1_PublicKey_class;
static VALUE Secp256k1_PrivateKey_class;
static VALUE Secp256k1_Signature_class;

// Forward definitions for all structures
typedef struct Context_dummy {
  secp256k1_context *ctx; // Context used by libsecp256k1 library
} Context;

typedef struct KeyPair_dummy {
  VALUE public_key;
  VALUE private_key;
} KeyPair;

typedef struct PublicKey_dummy {
  secp256k1_pubkey pubkey;
  Context *context;
} PublicKey;

typedef struct PrivateKey_dummy {
  unsigned char data[32]; // Bytes comprising the private key data
} PrivateKey;

typedef struct Signature_dummy {
  secp256k1_ecdsa_signature sig; // Signature object, contains 64-byte signature.
} Signature;

/**
 * Macro: SUCCESS
 * 
 * Determines whether or not the given function result was a success.
 */
#define SUCCESS(x) ((x) == RESULT_SUCCESS)

/**
 * Macro: FAILURE
 *
 * Indicates whether or not the given function result is a failure.
 */
#define FAILURE(x) !SUCCESS(x)

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
static ResultT
GenerateRandomBytes(unsigned char *out_bytes, size_t in_size)
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
    return RESULT_FAILURE;
  }

  return RESULT_SUCCESS;
}

/**
 * Computes the ECDSA signature of the given data.
 *
 * This method first computes the ECDSA signature of the given data (can be
 * text or binary data) and outputs both the raw libsecp256k1 signature and
 * the DER encoding of that signature.
 *
 * ECDSA signing involves the following steps:
 *   1. Compute the 32-byte SHA-256 hash of the given data.
 *   2. Sign the 32-byte hash using the private key provided.
 *
 * \param in_context libsecp256k1 context
 * \param in_data Data to be signed
 * \param in_data_len Length of data to be signed
 * \param in_private_key Private key to be used for signing
 * \param inout_der_signature_len Originally it should contain the total length
 *   of the out_der_signature buffer. Upon successful encoding it contains the
 *   actual length of the DER signature produced.
 * \param out_der_signature Buffer that will contain DER encoded signature
 * \param out_signature Signature produced during the signing proccess
 * \return RESULT_SUCCESS if the hash and signature were computed successfully,
 *   RESULT_FAILURE if signing failed or DER encoding failed.
 */
static ResultT
SignData(secp256k1_context *in_context,
         unsigned char *in_data,
         unsigned long in_data_len,
         unsigned char *in_private_key,
         unsigned long *inout_der_signature_len,
         unsigned char *out_der_signature,
         secp256k1_ecdsa_signature *out_signature)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];

  // Compute the SHA-256 hash of data
  SHA256(in_data, in_data_len, hash);

  // Sign the hash of the data
  if (secp256k1_ecdsa_sign(in_context,
                           out_signature,
                           hash,
                           in_private_key,
                           NULL,
                           NULL) != 1)
  {
    return RESULT_FAILURE;
  }

  // Produce the der encoding of the signature
  if (secp256k1_ecdsa_signature_serialize_der(in_context,
                                              out_der_signature,
                                              inout_der_signature_len,
                                              out_signature) == 1)
  {
    return RESULT_SUCCESS;
  }

  return RESULT_FAILURE;
}

/**
 * Secp256k1.generate_private_key_bytes
 *
 * Generate cryptographically secure 32 byte private key data.
 *
 * Raises:
 *   RuntimeError - If random number generation fails for any reason.
 */
static VALUE
Secp256k1_generate_private_key_bytes(VALUE self)
{
  unsigned char private_key_bytes[32];

  if (FAILURE(GenerateRandomBytes(private_key_bytes, 32)))
  {
    rb_raise(rb_eRuntimeError, "Random number generation failed.");
  }

  return rb_str_new((char*)private_key_bytes, 32);
}

//
// Secp256k1::PrivateKey class interface
//

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

/**
 * PrivateKey.generate
 *
 * Generates a new random private key.
 *
 * \return PrivateKey instance populated with randomly generated key.
 */
static VALUE
PrivateKey_generate(VALUE klass)
{
  VALUE result = rb_funcall(klass,
                            rb_intern("new"),
                            1,
                            Secp256k1_generate_private_key_bytes(Secp256k1_module));
  return result;
}

/**
 * PrivateKey#initialize
 *
 * Initialize a new private key with the given private key data.
 *
 * \param self allocated class instance
 * \param in_bytes private key data as 32 byte string
 * \raises ArgumentError If private key data is not 32 bytes long.
 */
static VALUE
PrivateKey_initialize(VALUE self, VALUE in_bytes)
{
  PrivateKey *private_key;

  Check_Type(in_bytes, T_STRING);

  if (RSTRING_LEN(in_bytes) != 32)
  {
    rb_raise(rb_eArgError, "private key data must be 32 bytes in length");
    return self;
  }

  Data_Get_Struct(self, PrivateKey, private_key);
  memcpy(private_key->data, RSTRING_PTR(in_bytes), 32);

  // Set the PrivateKey.data attribute for later reading
  rb_iv_set(self, "@data", in_bytes);

  return self;
}

//
// Secp256k1::Signature class interface
//

/* Allocate memory for Signature object */
static VALUE
Signature_alloc(VALUE klass)
{
  VALUE new_instance;
  Signature *signature;

  new_instance = Data_Make_Struct(klass,
                                  Signature,
                                  NULL,
                                  free,
                                  signature);
  memset(signature, 0, sizeof(Signature));

  return new_instance;
}

/**
 * Signature#initialize
 *
 * Initializes a signature object from a DER encoded signature.
 *
 * \param self
 * \param in_der_encoded_sig DER encoded signature data
 * \raises ArgumentError if signature was invalid or could not be decoded.
 */
static VALUE
Signature_initialize(VALUE self, VALUE in_der_encoded_sig)
{
  Check_Type(in_der_encoded_sig, T_STRING);

  rb_iv_set(self, "@der_encoded", in_der_encoded_sig);

  return self;
}

//
// Secp256k1::Context class interface
//

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

/**
 * Context#initialize
 *
 * Initialize a new libsecp256k1 context.
 *
 * \raises RuntimeError if context randomizatino fails.
 */
static VALUE
Context_initialize(VALUE self)
{
  Context *context;
  unsigned char seed[32];

  Data_Get_Struct(self, Context, context);

  context->ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
  );

  // Randomize the context at initialization time rather than before calls so
  // the same context can be used across threads safely.
  GenerateRandomBytes(seed, 32);
  if (secp256k1_context_randomize(context->ctx, seed) != 1)
  {
    rb_raise(rb_eRuntimeError, "Randomization of context failed.");
  }

  return self;
}

/**
 * Context#generate_key_pair
 *
 * Generate a new (public, private) key pair.
 */
static VALUE
Context_generate_key_pair(VALUE self)
{
  VALUE private_key;
  VALUE public_key;
  VALUE key_pair;

  private_key = PrivateKey_generate(Secp256k1_PrivateKey_class);
  public_key = rb_funcall(Secp256k1_PublicKey_class,
                          rb_intern("new"),
                          2,
                          self,
                          private_key);
  key_pair = rb_funcall(Secp256k1_KeyPair_class,
                        rb_intern("new"),
                        2,
                        public_key,
                        private_key);

  return key_pair;
}

/**
 * Context#public_key_from_data
 *
 * Loads a public key from compressed or uncompressed binary data.
 *
 * \param self
 * \param in_public_key_data Compressed or uncompressed binary public key data.
 */
static VALUE
Context_public_key_from_data(VALUE self, VALUE in_public_key_data)
{
  Context *context;
  PublicKey *public_key;
  unsigned char *public_key_data;
  VALUE result;

  Check_Type(in_public_key_data, T_STRING);

  Data_Get_Struct(self, Context, context);
  public_key_data = (unsigned char*)StringValuePtr(in_public_key_data);
  result = Data_Make_Struct(Secp256k1_PublicKey_class,
                            PublicKey,
                            NULL,
                            free,
                            public_key);
  public_key->context = context;

  if (secp256k1_ec_pubkey_parse(context->ctx,
                                &(public_key->pubkey),
                                public_key_data,
                                RSTRING_LEN(in_public_key_data)) != 1)
  {
    rb_raise(rb_eRuntimeError, "Invalid public key data");
  }

  return result;
}

/**
 * Context#key_pair_from_private_key
 *
 * Converts a binary private key into a key pair
 *
 * \param self
 * \param in_private_key_data Binary private key data to be used
 * \return A KeyPair initialized from the given private key data
 * \raises ArgumentError if the private key data is invalid or key derivation
 *   fails.
 */
static VALUE
Context_key_pair_from_private_key(VALUE self, VALUE in_private_key_data)
{
  Context *context;
  VALUE public_key;
  VALUE private_key;
  VALUE key_pair;
  unsigned char *private_key_data;

  // TODO: Move verification into PrivateKey_initialize?
  // Verify secret key data before attempting to recover key pair
  Data_Get_Struct(self, Context, context);
  private_key_data = (unsigned char*)StringValuePtr(in_private_key_data);

  if (secp256k1_ec_seckey_verify(context->ctx, private_key_data) != 1)
  {
    rb_raise(rb_eRuntimeError, "Invalid private key data.");
  }

  private_key = rb_funcall(Secp256k1_PrivateKey_class,
                           rb_intern("new"),
                           1,
                           in_private_key_data);
  public_key = rb_funcall(Secp256k1_PublicKey_class,
                          rb_intern("new"),
                          2,
                          self,
                          private_key);
  key_pair = rb_funcall(Secp256k1_KeyPair_class,
                        rb_intern("new"),
                        2,
                        public_key,
                        private_key);

  return key_pair;
}

/**
 * Context#signature_from_der_encoded
 *
 * Converts a DER encoded signature into a Secp256k1::Signature object.
 *
 * \param self
 * \param in_der_encoded_signature DER encoded signature as a binary string
 */
static VALUE
Context_signature_from_der_encoded(VALUE self, VALUE in_der_encoded_signature)
{
  Context *context;
  Signature *signature;
  VALUE signature_result;
  unsigned char *signature_data;

  Check_Type(in_der_encoded_signature, T_STRING);

  Data_Get_Struct(self, Context, context);
  signature_data = (unsigned char*)StringValuePtr(in_der_encoded_signature);

  signature_result = Data_Make_Struct(Secp256k1_Signature_class,
                                      Signature,
                                      NULL,
                                      free,
                                      signature);

  if (secp256k1_ecdsa_signature_parse_der(context->ctx,
                                          &(signature->sig),
                                          signature_data,
                                          RSTRING_LEN(in_der_encoded_signature)) != 1)
  {
    rb_raise(rb_eRuntimeError, "Invalid DER encoded signature.");
  }

  return signature_result;
}

/**
 * Context#sign
 *
 * Computes the ECDSA signature of the data using the secp256k1 EC.
 *
 * \param self
 * \param in_private_key Private key to use for signing
 * \param in_data Data to be signed
 * \raises RuntimeError if signing fails
 */
static VALUE
Context_sign(VALUE self, VALUE in_private_key, VALUE in_data)
{
  unsigned char *data_ptr;
  PrivateKey *private_key;
  Context *context;
  Signature *signature;
  unsigned char der_serialized_sig[512];
  unsigned long der_sig_len;
  VALUE signature_result;

  Check_Type(in_data, T_STRING);

  Data_Get_Struct(self, Context, context);
  Data_Get_Struct(in_private_key, PrivateKey, private_key);
  data_ptr = (unsigned char*)StringValuePtr(in_data);
  der_sig_len = 512;

  signature_result = Data_Make_Struct(Secp256k1_Signature_class,
                                      Signature,
                                      NULL,
                                      free,
                                      signature);

  // Attempt to sign the hash of the given data
  if (SUCCESS(SignData(context->ctx,
                       data_ptr,
                       RSTRING_LEN(in_data),
                       private_key->data,
                       &der_sig_len,
                       der_serialized_sig,
                       &(signature->sig))))
  {
    // Set Signature.der_encoded for posterity.
    rb_iv_set(signature_result,
              "@der_encoded",
              rb_str_new((char*)der_serialized_sig, der_sig_len));

    return signature_result;
  }

  rb_raise(rb_eRuntimeError, "Unable to compute signature");
}

/**
 * Context#verify
 *
 * Verifies that the signature by the holder of public key on message.
 *
 * \param self
 * \param in_signature Signature to be verified
 * \param in_pubkey Public key to verify signature against
 * \param in_message Message to verify signature of
 * \return Qtrue if the signature is valid, Qfalse otherwise.
 */
static VALUE
Context_verify(VALUE self, VALUE in_signature, VALUE in_pubkey, VALUE in_message)
{
  Context *context;
  PublicKey *public_key;
  Signature *signature;
  unsigned char *message_ptr;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  Check_Type(in_message, T_STRING);

  Data_Get_Struct(self, Context, context);
  Data_Get_Struct(in_pubkey, PublicKey, public_key);
  Data_Get_Struct(in_signature, Signature, signature);

  message_ptr = (unsigned char*)StringValuePtr(in_message);
  SHA256(message_ptr, RSTRING_LEN(in_message), hash);
  
  if (secp256k1_ecdsa_verify(context->ctx,
                             &(signature->sig),
                             hash,
                             &(public_key->pubkey)) == 1)
  {
    return Qtrue;
  }

  return Qfalse;
}

//
// Secp256k1::PublicKey class interface
//

static VALUE
PublicKey_alloc(VALUE klass)
{
  VALUE result;
  PublicKey *public_key;

  result = Data_Make_Struct(klass, PublicKey, NULL, free, public_key);

  return result;
}

/**
 * PublicKey#initialize
 *
 * Initialize a new public key from the given context and private key.
 *
 * \param in_context Context instance to be used in derivation
 * \param in_private_key PrivateKey to derive public key from
 * \return PublicKey instance initialized with data
 * \raises TypeError if private key data is invalid
 */
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

  public_key->context = context;

  return self;
}

/* PublicKey#as_uncompressed */
static VALUE
PublicKey_as_uncompressed(VALUE self)
{
  PublicKey *public_key;
  size_t serialized_pubkey_len = 65;
  unsigned char serialized_pubkey[65];

  Data_Get_Struct(self, PublicKey, public_key);

  if (public_key->context == NULL || public_key->context->ctx == NULL)
  {
    rb_raise(rb_eRuntimeError, "Public key context is NULL");
  }

  secp256k1_ec_pubkey_serialize(public_key->context->ctx,
                                serialized_pubkey,
                                &serialized_pubkey_len,
                                &(public_key->pubkey),
                                SECP256K1_EC_UNCOMPRESSED);

  return rb_str_new((char*)serialized_pubkey, serialized_pubkey_len);
}

/* PublicKey#as_compressed */
static VALUE
PublicKey_as_compressed(VALUE self)
{
  PublicKey *public_key;
  size_t serialized_pubkey_len = 65;
  unsigned char serialized_pubkey[65];

  Data_Get_Struct(self, PublicKey, public_key);

  secp256k1_ec_pubkey_serialize(public_key->context->ctx,
                                serialized_pubkey,
                                &serialized_pubkey_len,
                                &(public_key->pubkey),
                                SECP256K1_EC_COMPRESSED);

  return rb_str_new((char*)serialized_pubkey, serialized_pubkey_len);
}


//
// Secp256k1::KeyPair class interface
//

static VALUE
KeyPair_alloc(VALUE klass)
{
  VALUE result;
  KeyPair *key_pair;
  result = Data_Make_Struct(klass, KeyPair, NULL, free, key_pair);

  return result;
}

static VALUE
KeyPair_initialize(VALUE self, VALUE public_key, VALUE private_key)
{
  KeyPair *key_pair;

  Data_Get_Struct(self, KeyPair, key_pair);

  key_pair->public_key = public_key;
  key_pair->private_key = private_key;

  rb_iv_set(self, "@public_key", public_key);
  rb_iv_set(self, "@private_key", private_key);

  return self;
}

//
// Library initialization
//

void Init_rbsecp256k1()
{
  // Secp256k1
  Secp256k1_module = rb_define_module("Secp256k1");
  rb_define_singleton_method(Secp256k1_module,
                             "generate_private_key_bytes",
                             Secp256k1_generate_private_key_bytes,
                             0);

  // Secp256k1::Context
  Secp256k1_Context_class = rb_define_class_under(
    Secp256k1_module, "Context", rb_cObject
  );
  rb_define_alloc_func(Secp256k1_Context_class, Context_alloc);
  rb_define_method(Secp256k1_Context_class,
                   "initialize",
                   Context_initialize,
                   0);
  rb_define_method(Secp256k1_Context_class,
                   "generate_key_pair",
                   Context_generate_key_pair,
                   0);
  rb_define_method(Secp256k1_Context_class,
                   "key_pair_from_private_key",
                   Context_key_pair_from_private_key,
                   1);
  rb_define_method(Secp256k1_Context_class,
                   "public_key_from_data",
                   Context_public_key_from_data,
                   1);
  rb_define_method(Secp256k1_Context_class,
                   "sign",
                   Context_sign,
                   2);
  rb_define_method(Secp256k1_Context_class,
                   "verify",
                   Context_verify,
                   3);
  rb_define_method(Secp256k1_Context_class,
                   "signature_from_der_encoded",
                   Context_signature_from_der_encoded,
                   1);

  // Secp256k1::KeyPair
  Secp256k1_KeyPair_class = rb_define_class_under(Secp256k1_module,
                                                  "KeyPair",
                                                  rb_cObject);
  rb_define_alloc_func(Secp256k1_KeyPair_class, KeyPair_alloc);
  rb_define_attr(Secp256k1_KeyPair_class, "public_key", 1, 0);
  rb_define_attr(Secp256k1_KeyPair_class, "private_key", 1, 0);
  rb_define_method(Secp256k1_KeyPair_class,
                   "initialize",
                   KeyPair_initialize,
                   2);

  // Secp256k1::PublicKey
  Secp256k1_PublicKey_class = rb_define_class_under(Secp256k1_module,
                                                    "PublicKey",
                                                    rb_cObject);
  rb_define_alloc_func(Secp256k1_PublicKey_class, PublicKey_alloc);
  rb_define_method(Secp256k1_PublicKey_class,
                   "initialize",
                   PublicKey_initialize,
                   2);
  rb_define_method(Secp256k1_PublicKey_class,
                   "as_compressed",
                   PublicKey_as_compressed,
                   0);
  rb_define_method(Secp256k1_PublicKey_class,
                   "as_uncompressed",
                   PublicKey_as_uncompressed,
                   0);

  // Secp256k1::PrivateKey
  Secp256k1_PrivateKey_class = rb_define_class_under(
    Secp256k1_module, "PrivateKey", rb_cObject
  );
  rb_define_alloc_func(Secp256k1_PrivateKey_class, PrivateKey_alloc);
  rb_define_singleton_method(Secp256k1_PrivateKey_class,
                             "generate",
                             PrivateKey_generate,
                             0);
  rb_define_attr(Secp256k1_PrivateKey_class, "data", 1, 0);
  rb_define_method(Secp256k1_PrivateKey_class,
                   "initialize",
                   PrivateKey_initialize,
                   1);

  // Secp256k1::Signature
  Secp256k1_Signature_class = rb_define_class_under(Secp256k1_module,
                                                    "Signature",
                                                    rb_cObject);
  rb_define_alloc_func(Secp256k1_Signature_class, Signature_alloc);
  rb_define_attr(Secp256k1_Signature_class, "der_encoded", 1, 0);
  rb_define_method(Secp256k1_Signature_class,
                   "initialize",
                   Signature_initialize,
                   1);

}

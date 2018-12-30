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

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <secp256k1.h>

// Include recoverable signatures functionality if available
#ifdef HAVE_SECP256K1_RECOVERY_H
#include <secp256k1_recovery.h>
#endif // HAVE_SECP256K1_RECOVERY_H

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
// |--  RecoverableSignature
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

// Size of an uncompressed public key
const size_t UNCOMPRESSED_PUBKEY_SIZE_BYTES = 65;
// Size of a compressed public key
const size_t COMPRESSED_PUBKEY_SIZE_BYTES = 33;
// Size of a compact signature in bytes
const size_t COMPACT_SIG_SIZE_BYTES = 64;

// Globally define our module and its associated classes so we can instantiate
// objects from anywhere. The use of global variables seems to be inline with
// how the Ruby project builds its own extension gems.
static VALUE Secp256k1_module;
static VALUE Secp256k1_Context_class;
static VALUE Secp256k1_KeyPair_class;
static VALUE Secp256k1_PublicKey_class;
static VALUE Secp256k1_PrivateKey_class;
static VALUE Secp256k1_Signature_class;

#ifdef HAVE_SECP256K1_RECOVERY_H
static VALUE Secp256k1_RecoverableSignature_class;
#endif // HAVE_SECP256K1_RECOVERY_H

// Forward definitions for all structures
typedef struct Context_dummy {
  secp256k1_context *ctx; // Context used by libsecp256k1 library
} Context;

typedef struct KeyPair_dummy {
  VALUE public_key;
  VALUE private_key;
} KeyPair;

typedef struct PublicKey_dummy {
  secp256k1_pubkey pubkey; // Opaque object containing public key data
  secp256k1_context *ctx;
} PublicKey;

typedef struct PrivateKey_dummy {
  unsigned char data[32]; // Bytes comprising the private key data
  secp256k1_context *ctx;
} PrivateKey;

typedef struct Signature_dummy {
  secp256k1_ecdsa_signature sig; // Signature object, contains 64-byte signature
  secp256k1_context *ctx;
} Signature;

#ifdef HAVE_SECP256K1_RECOVERY_H
typedef struct RecoverableSignature_dummy {
  secp256k1_ecdsa_recoverable_signature sig; // Recoverable signature object
  secp256k1_context *ctx;
} RecoverableSignature;
#endif // HAVE_SECP256K1_RECOVERY_H

//
// Typed data definitions
//

// Context
static void
Context_free(void* in_context)
{
  Context *context;
  context = (Context*)in_context;
  secp256k1_context_destroy(context->ctx);
  xfree(context);
}

static const rb_data_type_t Context_DataType = {
  "Context",
  { 0, Context_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// PublicKey
static void
PublicKey_free(void *in_public_key)
{
  PublicKey *public_key;
  public_key = (PublicKey*)in_public_key;
  secp256k1_context_destroy(public_key->ctx);
  xfree(public_key);
}

static const rb_data_type_t PublicKey_DataType = {
  "PublicKey",
  { 0, PublicKey_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// PrivateKey
static void
PrivateKey_free(void *in_private_key)
{
  PrivateKey *private_key;
  private_key = (PrivateKey*)in_private_key;
  secp256k1_context_destroy(private_key->ctx);
  xfree(private_key);
}

static const rb_data_type_t PrivateKey_DataType = {
  "PrivateKey",
  { 0, PrivateKey_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// KeyPair
static void
KeyPair_mark(void *in_key_pair)
{
  KeyPair *key_pair = (KeyPair*)in_key_pair;

  // Mark both contained objects to ensure they are properly garbage collected
  rb_gc_mark(key_pair->public_key);
  rb_gc_mark(key_pair->private_key);
}

static void
KeyPair_free(void *self)
{
  xfree(self);
}

static const rb_data_type_t KeyPair_DataType = {
  "KeyPair",
  { KeyPair_mark, KeyPair_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// Signature
static void
Signature_free(void *in_signature)
{
  Signature *signature = (Signature*)in_signature;
  secp256k1_context_destroy(signature->ctx);
  xfree(signature);
}

static const rb_data_type_t Signature_DataType = {
  "Signature",
  { 0, Signature_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// RecoverableSignature
#ifdef HAVE_SECP256K1_RECOVERY_H
static void
RecoverableSignature_free(void *in_recoverable_signature)
{
  RecoverableSignature *recoverable_signature = (
    (RecoverableSignature*)in_recoverable_signature
  );

  secp256k1_context_destroy(recoverable_signature->ctx);
  xfree(recoverable_signature);
}

static const rb_data_type_t RecoverableSignature_DataType = {
  "RecoverableSignature",
  { 0, RecoverableSignature_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};
#endif // HAVE_SECP256K1_RECOVERY_H

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
 * text or binary data) and outputs both the raw libsecp256k1 signature.
 *
 * ECDSA signing involves the following steps:
 *   1. Compute the 32-byte SHA-256 hash of the given data.
 *   2. Sign the 32-byte hash using the private key provided.
 *
 * \param in_context libsecp256k1 context
 * \param in_data Data to be signed
 * \param in_data_len Length of data to be signed
 * \param in_private_key Private key to be used for signing
 * \param out_signature Signature produced during the signing proccess
 * \return RESULT_SUCCESS if the hash and signature were computed successfully,
 *   RESULT_FAILURE if signing failed or DER encoding failed.
 */
static ResultT
SignData(secp256k1_context *in_context,
         unsigned char *in_data,
         unsigned long in_data_len,
         unsigned char *in_private_key,
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
                           NULL) == 1)
  {
    return RESULT_SUCCESS;
  }

  return RESULT_FAILURE;
}

#ifdef HAVE_SECP256K1_RECOVERY_H

/**
 * Computes the recoverable ECDSA signature of the given data.
 *
 * ECDSA signing involves the following steps:
 *   1. Compute the 32-byte SHA-256 hash of the given data.
 *   2. Sign the 32-byte hash using the private key provided.
 *
 * \param in_context libsecp256k1 context
 * \param in_data Data to be signed
 * \param in_data_len Length of data to be signed
 * \param in_private_key Private key to be used for signing
 * \param out_signature Recoverable signature computed
 * \return RESULT_SUCCESS if the hash and signature were computed successfully,
 *   RESULT_FAILURE if signing failed or DER encoding failed.
 */
static ResultT
RecoverableSignData(secp256k1_context *in_context,
                    unsigned char *in_data,
                    unsigned long in_data_len,
                    unsigned char *in_private_key,
                    secp256k1_ecdsa_recoverable_signature *out_signature)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];

  // Compute the SHA-256 hash of data
  SHA256(in_data, in_data_len, hash);

  if (secp256k1_ecdsa_sign_recoverable(in_context,
                                       out_signature,
                                       hash,
                                       in_private_key,
                                       NULL,
                                       NULL) == 1)
  {
    return RESULT_SUCCESS;
  }

  return RESULT_FAILURE;
}

#endif // HAVE_SECP256K1_RECOVERY_H

//
// Secp256k1::KeyPair class interface
//

static VALUE
KeyPair_alloc(VALUE klass)
{
  KeyPair *key_pair;

  key_pair = ALLOC(KeyPair);

  return TypedData_Wrap_Struct(klass, &KeyPair_DataType, key_pair);
}

/**
 * Default constructor.
 *
 * @param in_public_key [Secp256k1::PublicKey] public key
 * @param in_private_key [Secp256k1::PrivateKey] private key
 * @return [Secp256k1::KeyPair] newly initialized key pair.
 */
static VALUE
KeyPair_initialize(VALUE self, VALUE in_public_key, VALUE in_private_key)
{
  KeyPair *key_pair;

  TypedData_Get_Struct(self, KeyPair, &KeyPair_DataType, key_pair);
  Check_TypedStruct(in_public_key, &PublicKey_DataType);
  Check_TypedStruct(in_private_key, &PrivateKey_DataType);

  key_pair->public_key = in_public_key;
  key_pair->private_key = in_private_key;

  rb_iv_set(self, "@public_key", in_public_key);
  rb_iv_set(self, "@private_key", in_private_key);

  return self;
}

//
// Secp256k1::PublicKey class interface
//

static VALUE
PublicKey_alloc(VALUE klass)
{
  VALUE result;
  PublicKey *public_key;

  public_key = ALLOC(PublicKey);
  MEMZERO(public_key, PublicKey, 1);
  result = TypedData_Wrap_Struct(klass, &PublicKey_DataType, public_key);

  return result;
}

static VALUE
PublicKey_create_from_private_key(Context *in_context,
                                  unsigned char *private_key_data)
{
  PublicKey *public_key;
  VALUE result;

  result = PublicKey_alloc(Secp256k1_PublicKey_class);
  TypedData_Get_Struct(result, PublicKey, &PublicKey_DataType, public_key);

  if (secp256k1_ec_pubkey_create(
        in_context->ctx,
        (&public_key->pubkey),
        private_key_data) != 1)
  {
    rb_raise(rb_eTypeError, "invalid private key data");
  }

  public_key->ctx = secp256k1_context_clone(in_context->ctx);
  return result;
}

static VALUE
PublicKey_create_from_data(Context *in_context,
                           unsigned char *in_public_key_data,
                           unsigned int in_public_key_data_len)
{
  PublicKey *public_key;
  VALUE result;

  result = PublicKey_alloc(Secp256k1_PublicKey_class);
  TypedData_Get_Struct(result, PublicKey, &PublicKey_DataType, public_key);

  if (secp256k1_ec_pubkey_parse(in_context->ctx,
                                &(public_key->pubkey),
                                in_public_key_data,
                                in_public_key_data_len) != 1)
  {
    rb_raise(rb_eRuntimeError, "invalid public key data");
  }

  public_key->ctx = secp256k1_context_clone(in_context->ctx);
  return result;
}

/**
 * @return [String] binary string containing the uncompressed representation
 *   of this public key.
 */
static VALUE
PublicKey_uncompressed(VALUE self)
{
  // TODO: Cache value after first computation
  PublicKey *public_key;
  size_t serialized_pubkey_len = UNCOMPRESSED_PUBKEY_SIZE_BYTES;
  unsigned char serialized_pubkey[UNCOMPRESSED_PUBKEY_SIZE_BYTES];

  TypedData_Get_Struct(self, PublicKey, &PublicKey_DataType, public_key);

  secp256k1_ec_pubkey_serialize(public_key->ctx,
                                serialized_pubkey,
                                &serialized_pubkey_len,
                                &(public_key->pubkey),
                                SECP256K1_EC_UNCOMPRESSED);

  return rb_str_new((char*)serialized_pubkey, serialized_pubkey_len);
}

/**
 * @return [String] binary string containing the compressed representation of
 *   this public key.
 */
static VALUE
PublicKey_compressed(VALUE self)
{
  // TODO: Cache value after first computation
  PublicKey *public_key;
  size_t serialized_pubkey_len = COMPRESSED_PUBKEY_SIZE_BYTES;
  unsigned char serialized_pubkey[COMPRESSED_PUBKEY_SIZE_BYTES];

  TypedData_Get_Struct(self, PublicKey, &PublicKey_DataType, public_key);

  secp256k1_ec_pubkey_serialize(public_key->ctx,
                                serialized_pubkey,
                                &serialized_pubkey_len,
                                &(public_key->pubkey),
                                SECP256K1_EC_COMPRESSED);

  return rb_str_new((char*)serialized_pubkey, serialized_pubkey_len);
}

//
// Secp256k1::PrivateKey class interface
//

static VALUE
PrivateKey_alloc(VALUE klass)
{
  VALUE new_instance;
  PrivateKey *private_key;

  private_key = ALLOC(PrivateKey);
  MEMZERO(private_key, PrivateKey, 1);
  new_instance = TypedData_Wrap_Struct(klass, &PrivateKey_DataType, private_key);

  return new_instance;
}

static VALUE
PrivateKey_create(Context *in_context, unsigned char *in_private_key_data)
{
  PrivateKey *private_key;
  VALUE result;

  if (secp256k1_ec_seckey_verify(in_context->ctx, in_private_key_data) != 1)
  {
    rb_raise(rb_eArgError, "invalid private key data");
  }

  result = PrivateKey_alloc(Secp256k1_PrivateKey_class);
  TypedData_Get_Struct(result, PrivateKey, &PrivateKey_DataType, private_key);
  MEMCPY(private_key->data, in_private_key_data, char, 32);
  private_key->ctx = secp256k1_context_clone(in_context->ctx);

  rb_iv_set(result, "@data", rb_str_new((char*)in_private_key_data, 32));

  return result;
}

//
// Secp256k1::Signature class interface
//

static VALUE
Signature_alloc(VALUE klass)
{
  VALUE new_instance;
  Signature *signature;

  signature = ALLOC(Signature);
  MEMZERO(signature, Signature, 1);
  new_instance = TypedData_Wrap_Struct(klass, &Signature_DataType, signature);

  return new_instance;
}

/**
 * Return Distinguished Encoding Rules (DER) encoded signature data.
 *
 * @return [String] binary string containing DER-encoded signature data.
 */
static VALUE
Signature_der_encoded(VALUE self)
{
  // TODO: Cache value after first computation
  Signature *signature;
  unsigned long der_signature_len;
  unsigned char der_signature[512];

  TypedData_Get_Struct(self, Signature, &Signature_DataType, signature);

  der_signature_len = 512;
  if (secp256k1_ecdsa_signature_serialize_der(signature->ctx,
                                              der_signature,
                                              &der_signature_len,
                                              &(signature->sig)) != 1)
  {
    rb_raise(rb_eRuntimeError, "could not compute DER encoded signature");
  }

  return rb_str_new((char*)der_signature, der_signature_len);
}

/**
 * Returns the 64 byte compact representation of this signature.
 *
 * @return [String] 64 byte binary string containing signature data.
 */
static VALUE
Signature_compact(VALUE self)
{
  // TODO: Cache value after first computation
  Signature *signature;
  unsigned char compact_signature[COMPACT_SIG_SIZE_BYTES];

  TypedData_Get_Struct(self, Signature, &Signature_DataType, signature);

  if (secp256k1_ecdsa_signature_serialize_compact(signature->ctx,
                                                  compact_signature,
                                                  &(signature->sig)) != 1)
  {
    rb_raise(rb_eRuntimeError, "unable to compute compact signature");
  }

  return rb_str_new((char*)compact_signature, COMPACT_SIG_SIZE_BYTES);
}

//
// Secp256k1::RecoverableSignature class interface
//

#ifdef HAVE_SECP256K1_RECOVERY_H

static VALUE
RecoverableSignature_alloc(VALUE klass)
{
  VALUE new_instance;
  RecoverableSignature *recoverable_signature;

  recoverable_signature = ALLOC(RecoverableSignature);
  MEMZERO(recoverable_signature, RecoverableSignature, 1);
  new_instance = TypedData_Wrap_Struct(
    klass, &RecoverableSignature_DataType, recoverable_signature
  );

  return new_instance;
}

/**
 * Returns the compact encoding of recoverable signature.
 *
 * @return [Array] first element is the 64 byte compact encoding of signature,
 *   the second element is the integer recovery ID.
 * @raise [RuntimeError] if signature serialization fails.
 */
static VALUE
RecoverableSignature_compact(VALUE self)
{
  RecoverableSignature *recoverable_signature;
  unsigned char compact_sig[64];
  int recovery_id;
  VALUE result;

  TypedData_Get_Struct(
    self,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );

  if (secp256k1_ecdsa_recoverable_signature_serialize_compact(
        recoverable_signature->ctx,
        compact_sig,
        &recovery_id,
        &(recoverable_signature->sig)) != 1)
  {
    rb_raise(rb_eRuntimeError, "unable to serialize recoverable signature");
  }

  // Create a new array with room for 2 elements and push data onto it
  result = rb_ary_new2(2);
  rb_ary_push(result, rb_str_new((char*)compact_sig, 64));
  rb_ary_push(result, rb_int_new(recovery_id));

  return result;
}

/**
 * Convert a recoverable signature to a non-recoverable signature.
 *
 * @return [Secp256k1::Signature] non-recoverable signature derived from this
 *   recoverable signature.
 */
static VALUE
RecoverableSignature_to_signature(VALUE self)
{
  RecoverableSignature *recoverable_signature;
  Signature *signature;
  VALUE result;

  TypedData_Get_Struct(
    self,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );

  result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(
    result,
    Signature,
    &Signature_DataType,
    signature
  );

  // NOTE: This method cannot fail
  secp256k1_ecdsa_recoverable_signature_convert(
    recoverable_signature->ctx,
    &(signature->sig),
    &(recoverable_signature->sig));

  signature->ctx = secp256k1_context_clone(recoverable_signature->ctx);
  return result;
}

/**
 * Attempts to recover the public key associated with this signature.
 *
 * @param in_data [String] data that this signature signed.
 * @return [Secp256k1::PublicKey] recovered public key.
 * @raise [RuntimeError] if the public key could not be recovered.
 */
static VALUE
RecoverableSignature_recover_public_key(VALUE self, VALUE in_data)
{
  RecoverableSignature *recoverable_signature;
  PublicKey *public_key;
  VALUE result;
  unsigned char *in_data_ptr;
  unsigned char hash[32];

  Check_Type(in_data, T_STRING);
  TypedData_Get_Struct(
    self,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );
  in_data_ptr = (unsigned char*)StringValuePtr(in_data);

  SHA256(in_data_ptr, RSTRING_LEN(in_data), hash);

  result = PublicKey_alloc(Secp256k1_PublicKey_class);
  TypedData_Get_Struct(result, PublicKey, &PublicKey_DataType, public_key);

  if (secp256k1_ecdsa_recover(recoverable_signature->ctx,
                              &(public_key->pubkey),
                              &(recoverable_signature->sig),
                              hash) == 1)
  {
    public_key->ctx = secp256k1_context_clone(recoverable_signature->ctx);
    return result;
  }

  rb_raise(rb_eRuntimeError, "unable to recover public key");
}

#endif // HAVE_SECP256K1_RECOVERY_H

//
// Secp256k1::Context class interface
//

/* Allocate a new context object */
static VALUE
Context_alloc(VALUE klass)
{
  VALUE new_instance;
  Context *context;

  context = ALLOC(Context);
  MEMZERO(context, Context, 1);

  new_instance = TypedData_Wrap_Struct(klass, &Context_DataType, context);

  return new_instance;
}

/**
 * Initialize a new context.
 *
 * Context initialization should be infrequent as it is an expensive operation.
 *
 * @return [Secp256k1::Context] 
 * @raise [RuntimeError] if context randomization fails.
 */
static VALUE
Context_initialize(VALUE self)
{
  Context *context;
  unsigned char seed[32];

  TypedData_Get_Struct(self, Context, &Context_DataType, context);

  context->ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
  );

  // Randomize the context at initialization time rather than before calls so
  // the same context can be used across threads safely.
  GenerateRandomBytes(seed, 32);
  if (secp256k1_context_randomize(context->ctx, seed) != 1)
  {
    rb_raise(rb_eRuntimeError, "context randomization failed");
  }

  return self;
}

/**
 * Generate a new public-private key pair.
 *
 * @return [Secp256k1::KeyPair] newly generated key pair.
 * @raise [RuntimeError] if private key generation fails.
 */
static VALUE
Context_generate_key_pair(VALUE self)
{
  Context *context;
  VALUE private_key;
  VALUE public_key;
  VALUE result;
  unsigned char private_key_bytes[32];

  if (FAILURE(GenerateRandomBytes(private_key_bytes, 32)))
  {
    rb_raise(rb_eRuntimeError, "unable to generate private key bytes.");
  }

  TypedData_Get_Struct(self, Context, &Context_DataType, context);

  private_key = PrivateKey_create(context, private_key_bytes);
  public_key = PublicKey_create_from_private_key(context, private_key_bytes);
  result = rb_funcall(
    Secp256k1_KeyPair_class,
    rb_intern("new"),
    2,
    public_key,
    private_key
  );

  return result;
}

/**
 * Loads a public key from compressed or uncompressed binary data.
 *
 * @param in_public_key_data [String] binary string with compressed or
 *   uncompressed public key data.
 * @return [Secp256k1::PublicKey] public key derived from data.
 * @raise [RuntimeError] if public key data is invalid.
 */
static VALUE
Context_public_key_from_data(VALUE self, VALUE in_public_key_data)
{
  Context *context;
  unsigned char *public_key_data;

  Check_Type(in_public_key_data, T_STRING);

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  public_key_data = (unsigned char*)StringValuePtr(in_public_key_data);
  return PublicKey_create_from_data(
    context,
    public_key_data,
    RSTRING_LEN(in_public_key_data)
  );
}

/**
 * Load a private key from binary data.
 *
 * @param in_private_key_data [String] 32 byte binary string of private key
 *   data.
 * @return [Secp256k1::PrivateKey] private key loaded from the given data.
 * @raise [ArgumentError] if private key data is not 32 bytes or is invalid.
 */
static VALUE
Context_private_key_from_data(VALUE self, VALUE in_private_key_data)
{
  Context *context;
  unsigned char *private_key_data;

  Check_Type(in_private_key_data, T_STRING);
  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  private_key_data = (unsigned char*)StringValuePtr(in_private_key_data);

  if (RSTRING_LEN(in_private_key_data) != 32)
  {
    rb_raise(rb_eArgError, "private key data must be 32 bytes in length");
  }

  return PrivateKey_create(context, private_key_data);
}

/**
 * Converts binary private key data into a new key pair.
 *
 * @param in_private_key_data [String] binary private key data
 * @return [Secp256k1::KeyPair] key pair initialized from the private key data.
 * @raise [ArgumentError] if the private key data is invalid or key derivation
 *   fails.
 */
static VALUE
Context_key_pair_from_private_key(VALUE self, VALUE in_private_key_data)
{
  Context *context;
  VALUE public_key;
  VALUE private_key;
  unsigned char *private_key_data;

  if (RSTRING_LEN(in_private_key_data) != 32)
  {
    rb_raise(rb_eArgError, "private key data must be 32 bytes in length");
  }

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  private_key_data = (unsigned char*)StringValuePtr(in_private_key_data);

  private_key = PrivateKey_create(context, private_key_data);
  public_key = PublicKey_create_from_private_key(context, private_key_data);

  return rb_funcall(
    Secp256k1_KeyPair_class,
    rb_intern("new"),
    2,
    public_key,
    private_key
  );
}

/**
 * Converts a DER encoded binary signature into a signature object.
 *
 * @param in_der_encoded_signature [String] DER encoded signature as binary
 *   string.
 * @return [Secp256k1::Signature] signature object initialized using signature
 *   data.
 * @raise [ArgumentError] if signature data is invalid.
 */
static VALUE
Context_signature_from_der_encoded(VALUE self, VALUE in_der_encoded_signature)
{
  Context *context;
  Signature *signature;
  VALUE signature_result;
  unsigned char *signature_data;

  Check_Type(in_der_encoded_signature, T_STRING);

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  signature_data = (unsigned char*)StringValuePtr(in_der_encoded_signature);

  signature_result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(signature_result, Signature, &Signature_DataType, signature);

  if (secp256k1_ecdsa_signature_parse_der(context->ctx,
                                          &(signature->sig),
                                          signature_data,
                                          RSTRING_LEN(in_der_encoded_signature)) != 1)
  {
    rb_raise(rb_eArgError, "invalid DER encoded signature");
  }

  signature->ctx = secp256k1_context_clone(context->ctx);
  return signature_result;
}

/**
 * Deserializes a Signature from 64-byte compact signature data.
 *
 * @param in_compact_signature [String] compact signature as 64-byte binary
 *   string.
 * @return [Secp256k1::Signature] object deserialized from compact signature.
 * @raise [ArgumentError] if signature data is invalid.
 */
static VALUE
Context_signature_from_compact(VALUE self, VALUE in_compact_signature)
{
  Context *context;
  Signature *signature;
  VALUE signature_result;
  unsigned char *signature_data;

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  signature_data = (unsigned char*)StringValuePtr(in_compact_signature);

  signature_result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(signature_result, Signature, &Signature_DataType, signature);

  if (secp256k1_ecdsa_signature_parse_compact(context->ctx,
                                              &(signature->sig),
                                              signature_data) != 1)
  {
    rb_raise(rb_eArgError, "invalid compact signature");
  }

  signature->ctx = secp256k1_context_clone(context->ctx);
  return signature_result;
}

/**
 * Computes the ECDSA signature of the data using the secp256k1 elliptic curve.
 *
 * @param in_private_key [Secp256k1::PrivateKey] private key to use for
 *   signing.
 * @param in_data [String] binary or text data to be signed.
 * @return [Secp256k1::Signature] signature resulting from signing data.
 * @raise [RuntimeError] if signature computation fails.
 */
static VALUE
Context_sign(VALUE self, VALUE in_private_key, VALUE in_data)
{
  unsigned char *data_ptr;
  PrivateKey *private_key;
  Context *context;
  Signature *signature;
  VALUE signature_result;

  Check_Type(in_data, T_STRING);

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(in_private_key, PrivateKey, &PrivateKey_DataType, private_key);
  data_ptr = (unsigned char*)StringValuePtr(in_data);

  signature_result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(signature_result, Signature, &Signature_DataType, signature);
 
  // Attempt to sign the hash of the given data
  if (SUCCESS(SignData(context->ctx,
                       data_ptr,
                       RSTRING_LEN(in_data),
                       private_key->data,
                       &(signature->sig))))
  {
    signature->ctx = secp256k1_context_clone(context->ctx);
    return signature_result;
  }

  rb_raise(rb_eRuntimeError, "unable to compute signature");
}

/**
 * Verifies that signature matches public key and data.
 *
 * @param in_signature [Secp256k1::Signature] signature to be verified.
 * @param in_pubkey [Secp256k1::PublicKey] public key to verify signature
 *   against.
 * @param in_data [String] text or binary data to verify signature against.
 * @return [Boolean] True if the signature is valid, false otherwise.
 */
static VALUE
Context_verify(VALUE self, VALUE in_signature, VALUE in_pubkey, VALUE in_data)
{
  Context *context;
  PublicKey *public_key;
  Signature *signature;
  unsigned char *data_ptr;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  Check_Type(in_data, T_STRING);

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(in_pubkey, PublicKey, &PublicKey_DataType, public_key);
  TypedData_Get_Struct(in_signature, Signature, &Signature_DataType, signature);

  data_ptr = (unsigned char*)StringValuePtr(in_data);
  SHA256(data_ptr, RSTRING_LEN(in_data), hash);
  
  if (secp256k1_ecdsa_verify(context->ctx,
                             &(signature->sig),
                             hash,
                             &(public_key->pubkey)) == 1)
  {
    return Qtrue;
  }

  return Qfalse;
}

// Context recoverable signature methods
#ifdef HAVE_SECP256K1_RECOVERY_H

/**
 * Computes the recoverable ECDSA signature of data signed with private key.
 *
 * @param in_private_key [Secp256k1::PrivateKey] private key to sign with.
 * @param in_data [String] data to be signed.
 * @return [Secp256k1::RecoverableSignature] recoverable signature produced by
 *   signing the SHA-256 hash of `in_data` with `in_private_key`.
 */
static VALUE
Context_sign_recoverable(VALUE self, VALUE in_private_key, VALUE in_data)
{
  Context *context;
  PrivateKey *private_key;
  RecoverableSignature *recoverable_signature;
  unsigned char *in_data_ptr;
  VALUE result;

  Check_Type(in_data, T_STRING);
  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(
    in_private_key, PrivateKey, &PrivateKey_DataType, private_key
  );
  in_data_ptr = (unsigned char*)StringValuePtr(in_data);

  result = RecoverableSignature_alloc(Secp256k1_RecoverableSignature_class);
  TypedData_Get_Struct(
    result,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );

  if (SUCCESS(RecoverableSignData(context->ctx,
                                  in_data_ptr,
                                  RSTRING_LEN(in_data),
                                  private_key->data,
                                  &(recoverable_signature->sig))))
  {
    recoverable_signature->ctx = secp256k1_context_clone(context->ctx);
    return result;
  }

  rb_raise(rb_eRuntimeError, "unable to compute recoverable signature");
}

/**
 * Loads recoverable signature from compact representation and recovery ID.
 *
 * @param in_compact_sig [String] binary string containing compact signature
 *   data.
 * @param in_recovery_id [Integer] recovery ID.
 * @return [Secp256k1::RecoverableSignature] signature parsed from data.
 * @raise [RuntimeError] if signature data or recovery ID is invalid.
 * @raise [ArgumentError] if compact signature is not 64 bytes.
 */
static VALUE
Context_recoverable_signature_from_compact(
  VALUE self, VALUE in_compact_sig, VALUE in_recovery_id)
{
  Context *context;
  RecoverableSignature *recoverable_signature;
  unsigned char *compact_sig;
  int recovery_id;
  VALUE result;

  Check_Type(in_compact_sig, T_STRING);
  Check_Type(in_recovery_id, T_FIXNUM);
  TypedData_Get_Struct(self, Context, &Context_DataType, context);

  compact_sig = (unsigned char*)StringValuePtr(in_compact_sig);
  recovery_id = FIX2INT(in_recovery_id);

  if (RSTRING_LEN(in_compact_sig) != 64)
  {
    rb_raise(rb_eArgError, "compact signature is not 64 bytes");
  }

  result = RecoverableSignature_alloc(Secp256k1_RecoverableSignature_class);
  TypedData_Get_Struct(
    result,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );

  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
        context->ctx,
        &(recoverable_signature->sig),
        compact_sig,
        recovery_id) == 1)
  {
    recoverable_signature->ctx = secp256k1_context_clone(context->ctx);
    return result;
  }
  
  rb_raise(rb_eRuntimeError, "unable to parse recoverable signature");
}

#endif // HAVE_SECP256K1_RECOVERY_H

//
// Secp256k1 module methods
//

/**
 * Indicates whether or not the libsecp256k1 recovery module was built.
 *
 * @return [Boolean] True if libsecp256k1 was built with the recovery module.
 */
static VALUE
Secp256k1_have_recovery(VALUE module)
{
#ifdef HAVE_SECP256K1_RECOVERY_H
  return Qtrue;
#else // HAVE_SECP256K1_RECOVERY_H
  return Qfalse;
#endif // HAVE_SECP256K1_RECOVERY_H
}

//
// Library initialization
//

void Init_rbsecp256k1()
{
  // NOTE: All classes derive from Data (rb_cData) rather than Object
  // (rb_cObject). This makes it so we don't have to call rb_undef_alloc_func
  // for each class and can instead simply define the allocation methods for
  // each class.
  //
  // See: https://github.com/ruby/ruby/blob/trunk/doc/extension.rdoc#encapsulate-c-data-into-a-ruby-object

  // Secp256k1
  Secp256k1_module = rb_define_module("Secp256k1");
  rb_define_singleton_method(
    Secp256k1_module,
    "have_recovery?",
    Secp256k1_have_recovery,
    0
  );

  // Secp256k1::Context
  Secp256k1_Context_class = rb_define_class_under(
    Secp256k1_module, "Context", rb_cData
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
                   "private_key_from_data",
                   Context_private_key_from_data,
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
  rb_define_method(Secp256k1_Context_class,
                   "signature_from_compact",
                   Context_signature_from_compact,
                   1);

  // Secp256k1::KeyPair
  Secp256k1_KeyPair_class = rb_define_class_under(Secp256k1_module,
                                                  "KeyPair",
                                                  rb_cData);
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
                                                    rb_cData);
  rb_define_alloc_func(Secp256k1_PublicKey_class, PublicKey_alloc);
  rb_define_method(Secp256k1_PublicKey_class,
                   "compressed",
                   PublicKey_compressed,
                   0);
  rb_define_method(Secp256k1_PublicKey_class,
                   "uncompressed",
                   PublicKey_uncompressed,
                   0);

  // Secp256k1::PrivateKey
  Secp256k1_PrivateKey_class = rb_define_class_under(
    Secp256k1_module, "PrivateKey", rb_cData
  );
  rb_define_alloc_func(Secp256k1_PrivateKey_class, PrivateKey_alloc);
  rb_define_attr(Secp256k1_PrivateKey_class, "data", 1, 0);

  // Secp256k1::Signature
  Secp256k1_Signature_class = rb_define_class_under(Secp256k1_module,
                                                    "Signature",
                                                    rb_cData);
  rb_define_alloc_func(Secp256k1_Signature_class, Signature_alloc);
  rb_define_method(Secp256k1_Signature_class,
                   "der_encoded",
                   Signature_der_encoded,
                   0);
  rb_define_method(Secp256k1_Signature_class,
                   "compact",
                   Signature_compact,
                   0);

#ifdef HAVE_SECP256K1_RECOVERY_H
  // Secp256k1::RecoverableSignature
  Secp256k1_RecoverableSignature_class = rb_define_class_under(
    Secp256k1_module,
    "RecoverableSignature",
    rb_cData
  );
  rb_define_alloc_func(
    Secp256k1_RecoverableSignature_class,
    RecoverableSignature_alloc
  );
  rb_define_method(
    Secp256k1_RecoverableSignature_class,
    "compact",
    RecoverableSignature_compact,
    0
  );
  rb_define_method(
    Secp256k1_RecoverableSignature_class,
    "to_signature",
    RecoverableSignature_to_signature,
    0
  );
  rb_define_method(
    Secp256k1_RecoverableSignature_class,
    "recover_public_key",
    RecoverableSignature_recover_public_key,
    1
  );

  // Context recoverable signature methods
  rb_define_method(
    Secp256k1_Context_class,
    "sign_recoverable",
    Context_sign_recoverable,
    2
  );
  rb_define_method(
    Secp256k1_Context_class,
    "recoverable_signature_from_compact",
    Context_recoverable_signature_from_compact,
    2
  );
#endif // HAVE_SECP256K1_RECOVERY_H
}

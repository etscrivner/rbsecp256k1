// rbsecp256k1.c - Ruby VM interfaces for library.
//
// Description:
// This library provides a low-level and high-performance Ruby wrapper around
// libsecp256k1. It includes functions for generating key pairs, signing data,
// and verifying signatures using the library.
//
// Dependencies:
//   * libsecp256k1

// Sanity check that we have the basic header file.
#ifndef HAVE_SECP256K1_H
  #error missing secp256k1.h during build
#endif // HAVE_SECP256K1_H

// Sanity check we have extrakeys module as we need it for keypair which is
// used by schnorrsig.
#ifndef HAVE_SECP256K1_EXTRAKEYS_H
  #error missing secp256k1_extrakeys.h during build
#endif // HAVE_SECP256K1_EXTRAKEYS_H

#include <ruby.h>
#include <secp256k1.h>

// Check for optional sub-modules. As a rule any secp256k1 submodule is
// optional and so should be blocked off using these ifdefs.
#ifdef HAVE_SECP256K1_RECOVERY_H
#include <secp256k1_recovery.h>
#endif // HAVE_SECP256K1_RECOVERY_H

#ifdef HAVE_SECP256K1_ECDH_H
#include <secp256k1_ecdh.h>
#endif // HAVE_SECP256K1_ECDH_H

#ifdef HAVE_SECP256K1_EXTRAKEYS_H
#include <secp256k1_extrakeys.h>
#endif // HAVE_SECP256K1_EXTRAKEYS_H

#ifdef HAVE_SECP256K1_SCHNORRSIG_H
#include <secp256k1_schnorrsig.h>
#endif // HAVE_SECP256K1_SCHNORRSIG_H

// High-level design:
//
// The Ruby wrapper is divided into the following hierarchical organization:
//
// +- Secp256k1 (Top-level module)
// |--  Context
// |--  KeyPair
// |--  PublicKey
// |--  XOnlyPublicKey
// |--  PrivateKey
// |--  RecoverableSignature (recovery module)
// |--  SharedSecret (ecdh module)
// |--  Signature
// |--  SchnorrSignature
//
// The Context class contains most of the methods that invoke libsecp256k1.
// The KeyPair, PublicKey, PrivateKey, RecoverableSignature, SharedSecret, and
// Signature objects act as data objects and are passed to various
// methods. Contexts are thread safe and can be used across
// applications. Context initialization is expensive so it is recommended that
// a single context be initialized and used throughout an application when
// possible.
//
// Exception Hierarchy:
//
// The following hierarchy is used for exceptions raised from the library:
//
// +- Error (Descends from StandardError)
// |-- SerializationError
// |-- DeserializationError

//
// The section below contains purely internal methods used exclusively by the
// C internals of the library.
//

// Size of an uncompressed public key
const size_t UNCOMPRESSED_PUBKEY_SIZE_BYTES = 65;
// Size of a compressed public key
const size_t COMPRESSED_PUBKEY_SIZE_BYTES = 33;
// Size of a serialized x-only public key
const size_t SERIALIZED_XONLY_PUBKEY_SIZE_BYTES = 32;
// Size of a compact signature in bytes
const size_t COMPACT_SIG_SIZE_BYTES = 64;
// Size of a schnorr signature in bytes
const size_t SCHNORR_SIG_SIZE_BYTES = 64;

// Globally define our module and its associated classes so we can instantiate
// objects from anywhere. The use of global variables seems to be inline with
// how the Ruby project builds its own extension gems.
static VALUE Secp256k1_module;
static VALUE Secp256k1_Error_class;
static VALUE Secp256k1_SerializationError_class;
static VALUE Secp256k1_DeserializationError_class;
static VALUE Secp256k1_Context_class;
static VALUE Secp256k1_KeyPair_class;
static VALUE Secp256k1_PublicKey_class;
static VALUE Secp256k1_PrivateKey_class;
static VALUE Secp256k1_Signature_class;
static VALUE Secp256k1_XOnlyPublicKey_class;

#ifdef HAVE_SECP256K1_RECOVERY_H
static VALUE Secp256k1_RecoverableSignature_class;
#endif // HAVE_SECP256K1_RECOVERY_H

#ifdef HAVE_SECP256K1_ECDH_H
static VALUE Secp256k1_SharedSecret_class;
#endif // HAVE_SECP256K1_ECDH_H

#ifdef HAVE_SECP256K1_SCHNORRSIG_H
static VALUE Secp256k1_SchnorrSignature_class;
#endif // HAVE_SECP256K1_SCHNORRSIG_H

// Forward definitions for all structures
typedef struct Context_dummy {
  secp256k1_context *ctx; // Context used by libsecp256k1 library
} Context;

typedef struct KeyPair_dummy {
  secp256k1_keypair keypair;
} KeyPair;

typedef struct PublicKey_dummy {
  secp256k1_pubkey pubkey; // Opaque object containing public key data
} PublicKey;

typedef struct PrivateKey_dummy {
  unsigned char data[32]; // Bytes comprising the private key data
} PrivateKey;

typedef struct XOnlyPublicKey_dummy {
  secp256k1_xonly_pubkey pubkey; // Opaque object representing an x-only pubkey.
} XOnlyPublicKey;

typedef struct Signature_dummy {
  secp256k1_ecdsa_signature sig; // Signature object, contains 64-byte signature
} Signature;

#ifdef HAVE_SECP256K1_RECOVERY_H
typedef struct RecoverableSignature_dummy {
  secp256k1_ecdsa_recoverable_signature sig; // Recoverable signature object
  secp256k1_context *ctx;
} RecoverableSignature;
#endif // HAVE_SECP256K1_RECOVERY_H

#ifdef HAVE_SECP256K1_ECDH_H
typedef struct SharedSecret_dummy {
  unsigned char data[32]; // Shared secret data
} SharedSecret;
#endif // HAVE_SECP256K1_ECDH_H

#ifdef HAVE_SECP256K1_SCHNORRSIG_H
typedef struct SchnorrSignature_dummy {
  unsigned char sig[64]; // Serialized schnorr signature data
} SchnorrSignature;
#endif // HAVE_SECP256K1_SCHNORRSIG_H
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
  xfree(public_key);
}

static const rb_data_type_t PublicKey_DataType = {
  "PublicKey",
  { 0, PublicKey_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// XOnlyPublicKey
static void
XOnlyPublicKey_free(void* in_xonly_pubkey)
{
  XOnlyPublicKey *xonly_pubkey;
  xonly_pubkey = (XOnlyPublicKey*)in_xonly_pubkey;
  xfree(xonly_pubkey);
}

static const rb_data_type_t XOnlyPublicKey_DataType = {
  "XOnlyPublicKey",
  { 0, XOnlyPublicKey_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// PrivateKey
static void
PrivateKey_free(void *in_private_key)
{
  PrivateKey *private_key;
  private_key = (PrivateKey*)in_private_key;

  /* Take the best practice recommendation from the libsecp256k1 example and
   * clear the secret from memory in case there are bugs that might allow an
   * attacker to leak memory.
   *
   * That being said its not clear how much control we actually have over Ruby
   * potentially copying the string version of this private key data.
   */
  memset(private_key->data, 0, 32);

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
KeyPair_free(void *in_keypair)
{
  KeyPair *keypair;
  keypair = (KeyPair*)in_keypair;
  xfree(keypair);
}

static const rb_data_type_t KeyPair_DataType = {
  "KeyPair",
  { 0, KeyPair_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};

// Signature
static void
Signature_free(void *in_signature)
{
  Signature *signature = (Signature*)in_signature;
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

// SharedSecret
#ifdef HAVE_SECP256K1_ECDH_H
static void
SharedSecret_free(void *in_shared_secret)
{
  SharedSecret *shared_secret;

  shared_secret = (SharedSecret*)in_shared_secret;
  xfree(shared_secret);
}

static const rb_data_type_t SharedSecret_DataType = {
  "SharedSecret",
  { 0, SharedSecret_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};
#endif // HAVE_SECP256K1_ECDH_H

// SchnorrSignature
#ifdef HAVE_SECP256K1_SCHNORRSIG_H
static void
SchnorrSignature_free(void *in_schnorr_sig)
{
  SchnorrSignature *schnorr_sig;

  schnorr_sig = (SchnorrSignature*)in_schnorr_sig;
  xfree(schnorr_sig);
}

static const rb_data_type_t SchnorrSignature_DataType = {
  "SchnorrSignature",
  { 0, SchnorrSignature_free, 0 },
  0, 0,
  RUBY_TYPED_FREE_IMMEDIATELY
};
#endif // HAVE_SECP256K1_SCHNORRSIG_H

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
 * Computes the ECDSA signature of the given 32-byte SHA-256 hash.
 *
 * \param in_context libsecp256k1 context
 * \param in_hash32 32-byte SHA-256 hash
 * \param in_private_key Private key to be used for signing
 * \param out_signature Signature produced during the signing proccess
 * \return RESULT_SUCCESS if the hash and signature were computed successfully,
 *   RESULT_FAILURE if signing failed or DER encoding failed.
 */
static ResultT
SignData(secp256k1_context *in_context,
         unsigned char *in_hash32,
         unsigned char *in_private_key,
         secp256k1_ecdsa_signature *out_signature)
{
  // Sign the hash of the data
  if (secp256k1_ecdsa_sign(in_context,
                           out_signature,
                           in_hash32,
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
 * \param in_hash32 32-byte SHA-256 hash to sign
 * \param in_private_key Private key to be used for signing
 * \param out_signature Recoverable signature computed
 * \return RESULT_SUCCESS if the hash and signature were computed successfully,
 *   RESULT_FAILURE if signing failed or DER encoding failed.
 */
static ResultT
RecoverableSignData(secp256k1_context *in_context,
                    unsigned char *in_hash32,
                    unsigned char *in_private_key,
                    secp256k1_ecdsa_recoverable_signature *out_signature)
{
  if (secp256k1_ecdsa_sign_recoverable(in_context,
                                       out_signature,
                                       in_hash32,
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
// Secp256k1::XOnlyPublicKey class interface
//

static VALUE
XOnlyPublicKey_alloc(VALUE klass)
{
  VALUE result;
  XOnlyPublicKey* xonly_pubkey;

  xonly_pubkey = ALLOC(XOnlyPublicKey);
  MEMZERO(xonly_pubkey, XOnlyPublicKey, 1);
  result = TypedData_Wrap_Struct(klass, &XOnlyPublicKey_DataType, xonly_pubkey);

  return result;
}

static VALUE
XOnlyPublicKey_create_from_data(unsigned char *in_xonly_pubkey32)
{
  XOnlyPublicKey *xonly_pubkey;
  VALUE result;

  result = XOnlyPublicKey_alloc(Secp256k1_XOnlyPublicKey_class);
  TypedData_Get_Struct(result, XOnlyPublicKey, &XOnlyPublicKey_DataType, xonly_pubkey);

  if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &xonly_pubkey->pubkey, in_xonly_pubkey32) != 1)
  {
    rb_raise(Secp256k1_DeserializationError_class, "invalid x-only public key data");
    return Qnil;
  }

  return result;
}

/**
 * Loads an x-only public key from serialized data.
 *
 * @param in_xonly_public_key_serialized [String] binary string with serialized
 * data.
 * @return [Secp256k1::XOnlyPublicKey] x-only public key derived from data.
 * @raise [Secp256k1::DeserializationError] if x-only public key data is invalid
 */
static VALUE
XOnlyPublicKey_from_data(VALUE klass, VALUE in_xonly_public_key_serialized)
{
  unsigned char *xonly_pubkey_data;

  Check_Type(in_xonly_public_key_serialized, T_STRING);
  if (RSTRING_LEN(in_xonly_public_key_serialized) != 32)
  {
    rb_raise(Secp256k1_DeserializationError_class, "x-only public key data must be 32 bytes in length");
    return Qnil;
  }

  xonly_pubkey_data = (unsigned char*)StringValuePtr(in_xonly_public_key_serialized);
  return XOnlyPublicKey_create_from_data(xonly_pubkey_data);
}

/**
 * Returns the 32-byte serialized version of this x-only public key.
 *
 * @return [String] 32-byte binary string containing serialized x-only public
 * key.
 */
static VALUE
XOnlyPublicKey_serialized(VALUE self)
{
  XOnlyPublicKey* xonly_pubkey;
  unsigned char out[SERIALIZED_XONLY_PUBKEY_SIZE_BYTES];

  TypedData_Get_Struct(self, XOnlyPublicKey, &XOnlyPublicKey_DataType, xonly_pubkey);

  if (secp256k1_xonly_pubkey_serialize(secp256k1_context_static, out, &xonly_pubkey->pubkey) != 1)
  {
    rb_raise(Secp256k1_SerializationError_class, "failed to serialize x-only public key");
    return Qnil;
  }

  return rb_str_new((char*)out, SERIALIZED_XONLY_PUBKEY_SIZE_BYTES);
}

/**
 * Compare two x-only public keys.
 *
 * @param other [Secp256k1::XOnlyPublicKey] x-only public key to compare.
 * @return [Boolean] true if they are equal, false otherwise.
 */
static VALUE
XOnlyPublicKey_equals(VALUE self, VALUE other)
{
  XOnlyPublicKey *lhs;
  XOnlyPublicKey *rhs;

  TypedData_Get_Struct(self, XOnlyPublicKey, &XOnlyPublicKey_DataType, lhs);
  TypedData_Get_Struct(other, XOnlyPublicKey, &XOnlyPublicKey_DataType, rhs);

  if (secp256k1_xonly_pubkey_cmp(secp256k1_context_static, &lhs->pubkey, &rhs->pubkey) == 0)
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

  public_key = ALLOC(PublicKey);
  MEMZERO(public_key, PublicKey, 1);
  result = TypedData_Wrap_Struct(klass, &PublicKey_DataType, public_key);

  return result;
}

static VALUE
PublicKey_create_from_data(unsigned char *in_public_key_data,
                           unsigned int in_public_key_data_len)
{
  PublicKey *public_key;
  VALUE result;

  result = PublicKey_alloc(Secp256k1_PublicKey_class);
  TypedData_Get_Struct(result, PublicKey, &PublicKey_DataType, public_key);

  if (secp256k1_ec_pubkey_parse(secp256k1_context_static,
                                &(public_key->pubkey),
                                in_public_key_data,
                                in_public_key_data_len) != 1)
  {
    rb_raise(Secp256k1_DeserializationError_class, "invalid public key data");
    return Qnil;
  }

  return result;
}

/**
 * Loads a public key from compressed or uncompressed binary data.
 *
 * @param in_public_key_data [String] binary string with compressed or
 *   uncompressed public key data.
 * @return [Secp256k1::PublicKey] public key derived from data.
 * @raise [Secp256k1::DeserializationError] if public key data is invalid.
 */
static VALUE
PublicKey_from_data(VALUE klass, VALUE in_public_key_data)
{
  unsigned char *public_key_data;

  Check_Type(in_public_key_data, T_STRING);

  public_key_data = (unsigned char*)StringValuePtr(in_public_key_data);
  return PublicKey_create_from_data(
    public_key_data,
    (int)RSTRING_LEN(in_public_key_data)
  );
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

  secp256k1_ec_pubkey_serialize(secp256k1_context_static,
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

  secp256k1_ec_pubkey_serialize(secp256k1_context_static,
                                serialized_pubkey,
                                &serialized_pubkey_len,
                                &(public_key->pubkey),
                                SECP256K1_EC_COMPRESSED);

  return rb_str_new((char*)serialized_pubkey, serialized_pubkey_len);
}

/**
 * Returns the x-only public key equivalent of this public key.
 *
 * @return [Secp256k1::XOnlyPublicKey] x-only public key
 */
static VALUE
PublicKey_to_xonly(VALUE self)
{
  PublicKey *public_key;
  XOnlyPublicKey *xonly_pubkey;
  VALUE result;

  TypedData_Get_Struct(self, PublicKey, &PublicKey_DataType, public_key);

  result = XOnlyPublicKey_alloc(Secp256k1_XOnlyPublicKey_class);
  TypedData_Get_Struct(result, XOnlyPublicKey, &XOnlyPublicKey_DataType, xonly_pubkey);

  if (secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static,
                                         &xonly_pubkey->pubkey,
                                         NULL,
                                         &public_key->pubkey) != 1)
  {
    rb_raise(Secp256k1_Error_class, "failed to convert pubkey to x-only pubkey");
    return Qnil;
  }

  return result;
}

/**
 * Compares two public keys.
 *
 * Public keys are considered equal if their compressed representations match.
 *
 * @param other [Secp256k1::PublicKey] public key to compare.
 * @return [Boolean] true if the public keys are identical, false otherwise.
 */
static VALUE
PublicKey_equals(VALUE self, VALUE other)
{
  PublicKey *lhs;
  PublicKey *rhs;
  unsigned char lhs_compressed[33];
  unsigned char rhs_compressed[33];
  size_t lhs_len;
  size_t rhs_len;

  lhs_len = 33;
  rhs_len = 33;

  TypedData_Get_Struct(self, PublicKey, &PublicKey_DataType, lhs);
  TypedData_Get_Struct(other, PublicKey, &PublicKey_DataType, rhs);

  secp256k1_ec_pubkey_serialize(
    secp256k1_context_static,
    lhs_compressed,
    &lhs_len,
    &(lhs->pubkey),
    SECP256K1_EC_COMPRESSED
  );
  secp256k1_ec_pubkey_serialize(
    secp256k1_context_static,
    rhs_compressed,
    &rhs_len,
    &(rhs->pubkey),
    SECP256K1_EC_COMPRESSED
  );

  if (lhs_len == rhs_len &&
      memcmp(lhs_compressed, rhs_compressed, lhs_len) == 0)
  {
    return Qtrue;
  }

  return Qfalse;
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

/* Internal-only method for creating a private key from secret data */
static VALUE
PrivateKey_create(unsigned char *in_private_key_data)
{
  PrivateKey *private_key;
  VALUE result;

  if (secp256k1_ec_seckey_verify(secp256k1_context_static,
                                 in_private_key_data) != 1)
  {
    rb_raise(Secp256k1_Error_class, "invalid private key data");
    return Qnil;
  }

  result = PrivateKey_alloc(Secp256k1_PrivateKey_class);
  TypedData_Get_Struct(result, PrivateKey, &PrivateKey_DataType, private_key);
  MEMCPY(private_key->data, in_private_key_data, char, 32);

  return result;
}

/**
 * Returns binary string of private key data.
 *
 * @return [String] 32 byte binary string of private key data.
 */
static VALUE
PrivateKey_data(VALUE self)
{
  PrivateKey *private_key;

  TypedData_Get_Struct(self, PrivateKey, &PrivateKey_DataType, private_key);

  return(rb_str_new((char*)private_key->data, 32));
}

/**
 * Load a private key from binary data.
 *
 * @param in_private_key_data [String] 32 byte binary string of private key
 *   data.
 * @return [Secp256k1::PrivateKey] private key loaded from the given data.
 * @raise [Secp256k1::Error] if private key data is not 32 bytes or is invalid.
 */
static VALUE
PrivateKey_from_data(VALUE klass, VALUE in_private_key_data)
{
  unsigned char *private_key_data;

  Check_Type(in_private_key_data, T_STRING);
  if (RSTRING_LEN(in_private_key_data) != 32)
  {
    rb_raise(
      Secp256k1_Error_class,
      "private key data must be 32 bytes in length"
    );
    return Qnil;
  }

  private_key_data = (unsigned char*)StringValuePtr(in_private_key_data);
  return PrivateKey_create(private_key_data);
}

/**
 * Compare two private keys.
 *
 * Private keys are considered equal if their data fields are identical.
 *
 * @param other [Secp256k1::PrivateKey] private key to compare. 
 * @return [Boolean] true if they are equal, false otherwise.
 */
static VALUE
PrivateKey_equals(VALUE self, VALUE other)
{
  PrivateKey *lhs;
  PrivateKey *rhs;

  TypedData_Get_Struct(self, PrivateKey, &PrivateKey_DataType, lhs);
  TypedData_Get_Struct(other, PrivateKey, &PrivateKey_DataType, rhs);

  if (memcmp(lhs->data, rhs->data, 32) == 0)
  {
    return Qtrue;
  }

  return Qfalse;
}

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
 * Retrieve the public key for the given key pair.
 *
 * @return [Secp256k1::PublicKey] public key corresponding to private key.
 */
static VALUE
KeyPair_public_key(VALUE self)
{
  KeyPair *key_pair;
  VALUE result;
  PublicKey *public_key;

  TypedData_Get_Struct(self, KeyPair, &KeyPair_DataType, key_pair);

  result = PublicKey_alloc(Secp256k1_PublicKey_class);
  TypedData_Get_Struct(result, PublicKey, &PublicKey_DataType, public_key);

  if (secp256k1_keypair_pub(secp256k1_context_static, &public_key->pubkey, &key_pair->keypair) == 0)
  {
    rb_raise(Secp256k1_Error_class, "failed to derive public key from keypair");
    return Qnil;
  }

  return result;
}

/**
 * Retrieve the x-only public key for the given key pair.
 *
 * @return [Secp256k1::XOnlyPublicKey] x-only public key corresponding to
 * private key.
 */
static VALUE
KeyPair_xonly_public_key(VALUE self)
{
  KeyPair *key_pair;
  VALUE result;
  XOnlyPublicKey *xonly_pubkey;

  TypedData_Get_Struct(self, KeyPair, &KeyPair_DataType, key_pair);

  result = XOnlyPublicKey_alloc(Secp256k1_XOnlyPublicKey_class);
  TypedData_Get_Struct(result, XOnlyPublicKey, &XOnlyPublicKey_DataType, xonly_pubkey);

  if (secp256k1_keypair_xonly_pub(secp256k1_context_static, &xonly_pubkey->pubkey, NULL, &key_pair->keypair) == 0)
  {
    rb_raise(Secp256k1_Error_class, "failed to derive x-only public key from keypair");
    return Qnil;
  }

  return result;
}

/**
 * Retrieve the private key for the given key pair.
 *
 * @return [Secp256k1::PrivateKey] public key corresponding to private key.
 */
static VALUE
KeyPair_private_key(VALUE self)
{
  KeyPair *key_pair;
  unsigned char private_key_data[32];

  TypedData_Get_Struct(self, KeyPair, &KeyPair_DataType, key_pair);

  if (secp256k1_keypair_sec(secp256k1_context_static, private_key_data, &key_pair->keypair) == 0)
  {
    rb_raise(Secp256k1_Error_class, "failed to derive private key from keypair");
    return Qnil;
  }

  return PrivateKey_create(private_key_data);
}

/**
 * Compare two key pairs.
 *
 * Two key pairs are equal if they have the same public and private key. The
 * keys are compared using their own comparison operators.
 *
 * @param other [Secp256k1::KeyPair] key pair to compare to.
 * @return [Boolean] true if the keys match, false otherwise.
 */
static VALUE
KeyPair_equals(VALUE self, VALUE other)
{
  KeyPair *lhs;
  KeyPair *rhs;

  TypedData_Get_Struct(self, KeyPair, &KeyPair_DataType, lhs);
  TypedData_Get_Struct(other, KeyPair, &KeyPair_DataType, rhs);

  if (memcmp(&lhs->keypair, &rhs->keypair, sizeof(secp256k1_keypair)) == 0)
  {
    return Qtrue;
  }

  return Qfalse;
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
 * Deserializes a Signature from 64-byte compact signature data.
 *
 * @param in_compact_signature [String] compact signature as 64-byte binary
 *   string.
 * @return [Secp256k1::Signature] object deserialized from compact signature.
 * @raise [Secp256k1::DeserializationError] if signature data is invalid.
 */
static VALUE
Signature_from_compact(VALUE klass, VALUE in_compact_signature)
{
  Signature *signature;
  VALUE signature_result;
  unsigned char *signature_data;

  Check_Type(in_compact_signature, T_STRING);

  if (RSTRING_LEN(in_compact_signature) != 64)
  {
    rb_raise(Secp256k1_Error_class, "compact signature must be 64 bytes");
  }

  signature_data = (unsigned char*)StringValuePtr(in_compact_signature);

  signature_result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(signature_result, Signature, &Signature_DataType, signature);

  if (secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static,
                                              &(signature->sig),
                                              signature_data) != 1)
  {
    rb_raise(Secp256k1_DeserializationError_class, "invalid compact signature");
    return Qnil;
  }

  return signature_result;
}

/**
 * Converts a DER encoded binary signature into a signature object.
 *
 * @param in_der_encoded_signature [String] DER encoded signature as binary
 *   string.
 * @return [Secp256k1::Signature] signature object initialized using signature
 *   data.
 * @raise [Secp256k1::DeserializationError] if signature data is invalid.
 */
static VALUE
Signature_from_der_encoded(VALUE klass, VALUE in_der_encoded_signature)
{
  Signature *signature;
  VALUE signature_result;
  unsigned char *signature_data;

  Check_Type(in_der_encoded_signature, T_STRING);

  signature_data = (unsigned char*)StringValuePtr(in_der_encoded_signature);

  signature_result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(signature_result, Signature, &Signature_DataType, signature);

  if (secp256k1_ecdsa_signature_parse_der(secp256k1_context_static,
                                          &(signature->sig),
                                          signature_data,
                                          RSTRING_LEN(in_der_encoded_signature)) != 1)
  {
    rb_raise(Secp256k1_DeserializationError_class, "invalid DER encoded signature");
    return Qnil;
  }

  return signature_result;
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
  unsigned char der_signature[72];

  TypedData_Get_Struct(self, Signature, &Signature_DataType, signature);

  der_signature_len = 72;
  if (secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static,
                                              der_signature,
                                              &der_signature_len,
                                              &(signature->sig)) != 1)
  {
    rb_raise(
      Secp256k1_SerializationError_class,
      "could not compute DER encoded signature"
    );
    return Qnil;
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

  if (secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static,
                                                  compact_signature,
                                                  &(signature->sig)) != 1)
  {
    rb_raise(
      Secp256k1_SerializationError_class,
      "unable to compute compact signature"
    );
    return Qnil;
  }

  return rb_str_new((char*)compact_signature, COMPACT_SIG_SIZE_BYTES);
}

/**
 * Returns the normalized lower-S form of this signature.
 *
 * This can be useful when importing signatures generated by other applications
 * that may not be normalized. Non-normalized signatures are potentially
 * forgeable.
 *
 * @return [Array] first element is a boolean that is `true` if the signature
 *   was normalized, false otherwise. The second element is a `Signature`
 *   object corresponding to the normalized signature.
 */
static VALUE
Signature_normalized(VALUE self)
{
  VALUE result_sig;
  VALUE was_normalized;
  VALUE result;
  Signature *signature;
  Signature *normalized_signature;

  TypedData_Get_Struct(self, Signature, &Signature_DataType, signature);
  result_sig = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(
    result_sig, Signature, &Signature_DataType, normalized_signature
  );

  was_normalized = Qfalse;
  if (secp256k1_ecdsa_signature_normalize(
        secp256k1_context_static,
        &(normalized_signature->sig),
        &(signature->sig)) == 1)
  {
    was_normalized = Qtrue;
  }

  result = rb_ary_new2(2);
  rb_ary_push(result, was_normalized);
  rb_ary_push(result, result_sig);

  return result;
}

/**
 * Compares two signatures.
 *
 * Two signatures are equal if their compact encodings are identical.
 *
 * @param other [Secp256k1::Signature] signature to compare
 * @return [Boolean] true if signatures match, false otherwise.
 */
static VALUE
Signature_equals(VALUE self, VALUE other)
{
  Signature *lhs;
  Signature *rhs;
  unsigned char lhs_compact[64];
  unsigned char rhs_compact[64];

  TypedData_Get_Struct(self, Signature, &Signature_DataType, lhs);
  TypedData_Get_Struct(other, Signature, &Signature_DataType, rhs);

  secp256k1_ecdsa_signature_serialize_compact(
    secp256k1_context_static, lhs_compact, &(lhs->sig)
  );
  secp256k1_ecdsa_signature_serialize_compact(
    secp256k1_context_static, rhs_compact, &(rhs->sig)
  );

  if (memcmp(lhs_compact, rhs_compact, 64) == 0)
  {
    return Qtrue;
  }

  return Qfalse;
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
 * @raise [Secp256k1::SerializationError] if signature serialization fails.
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
    rb_raise(
      Secp256k1_SerializationError_class,
      "unable to serialize recoverable signature"
    );
    return Qnil;
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

  return result;
}

/**
 * Attempts to recover the public key associated with this signature.
 *
 * @param in_hash32 [String] 32-byte SHA-256 hash of data.
 * @return [Secp256k1::PublicKey] recovered public key.
 * @raise [Secp256k1::Error] if hash given is not 32 bytes.
 * @raise [Secp256k1::DeserializationError] if public key could not be
 *   recovered.
 */
static VALUE
RecoverableSignature_recover_public_key(VALUE self, VALUE in_hash32)
{
  RecoverableSignature *recoverable_signature;
  PublicKey *public_key;
  VALUE result;
  unsigned char *hash32;

  Check_Type(in_hash32, T_STRING);
  if (RSTRING_LEN(in_hash32) != 32)
  {
    rb_raise(Secp256k1_Error_class, "in_hash32 is not 32 bytes in length");
    return Qnil;
  }

  TypedData_Get_Struct(
    self,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );
  hash32 = (unsigned char*)StringValuePtr(in_hash32);

  result = PublicKey_alloc(Secp256k1_PublicKey_class);
  TypedData_Get_Struct(result, PublicKey, &PublicKey_DataType, public_key);

  if (secp256k1_ecdsa_recover(recoverable_signature->ctx,
                              &(public_key->pubkey),
                              &(recoverable_signature->sig),
                              hash32) == 1)
  {
    return result;
  }

  rb_raise(Secp256k1_DeserializationError_class, "unable to recover public key");
}

/**
 * Compares two recoverable signatures.
 *
 * Two recoverable signatures their secp256k1_ecdsa_recoverable_signature data
 * is identical.
 *
 * @param other [Secp256k1::RecoverableSignature] recoverable signature to
 *   compare.
 * @return [Boolean] true if the recoverable signatures are identical, false
 *   otherwise.
 */
static VALUE
RecoverableSignature_equals(VALUE self, VALUE other)
{
  RecoverableSignature *lhs;
  RecoverableSignature *rhs;

  TypedData_Get_Struct(
    self, RecoverableSignature, &RecoverableSignature_DataType, lhs
  );
  TypedData_Get_Struct(
    other, RecoverableSignature, &RecoverableSignature_DataType, rhs
  );

  // NOTE: It is safe to directly compare these data structures rather than
  // first serializing and then comparing.
  if (memcmp(&(lhs->sig),
             &(rhs->sig),
             sizeof(secp256k1_ecdsa_recoverable_signature)) == 0)
  {
    return Qtrue;
  }

  return Qfalse;
}

#endif // HAVE_SECP256K1_RECOVERY_H

//
// Secp256k1::SharedSecret class interface
//

#ifdef HAVE_SECP256K1_ECDH_H

static VALUE
SharedSecret_alloc(VALUE klass)
{
  VALUE new_instance;
  SharedSecret *shared_secret;

  shared_secret = ALLOC(SharedSecret);
  MEMZERO(shared_secret, SharedSecret, 1);
  new_instance = TypedData_Wrap_Struct(
  klass, &SharedSecret_DataType, shared_secret
  );

  return new_instance;
}

#endif // HAVE_SECP256K1_ECDH_H

//
// Secp256k1::SchnorrSignature class interface
//

#ifdef HAVE_SECP256K1_SCHNORRSIG_H

static VALUE
SchnorrSignature_alloc(VALUE klass)
{
  VALUE new_instance;
  SchnorrSignature *schnorr_sig;

  schnorr_sig = ALLOC(SchnorrSignature);
  MEMZERO(schnorr_sig, SchnorrSignature, 1);
  new_instance = TypedData_Wrap_Struct(klass, &SchnorrSignature_DataType, schnorr_sig);

  return new_instance;
}

static VALUE
SchnorrSignature_from_data(VALUE klass, VALUE in_data)
{
  SchnorrSignature* sig;
  VALUE result;
  unsigned char* schnorr_data;

  Check_Type(in_data, T_STRING);
  if (RSTRING_LEN(in_data) != SCHNORR_SIG_SIZE_BYTES)
  {
    rb_raise(Secp256k1_DeserializationError_class, "schnorr signature data must be 64 bytes in length");
    return Qnil;
  }

  schnorr_data = (unsigned char*)StringValuePtr(in_data);

  result = SchnorrSignature_alloc(Secp256k1_SchnorrSignature_class);
  TypedData_Get_Struct(result, SchnorrSignature, &SchnorrSignature_DataType, sig);

  memcpy(sig->sig, schnorr_data, SCHNORR_SIG_SIZE_BYTES);

  return result;
}

static VALUE
SchnorrSignature_serialized(VALUE self)
{
  SchnorrSignature *schnorr_sig;

  TypedData_Get_Struct(self, SchnorrSignature, &SchnorrSignature_DataType, schnorr_sig);

  return rb_str_new((char*)schnorr_sig->sig, SCHNORR_SIG_SIZE_BYTES);
}

static VALUE
SchnorrSignature_verify(VALUE self, VALUE in_message, VALUE in_xonly_pubkey)
{
  XOnlyPublicKey *xonly_pubkey;
  SchnorrSignature *schnorr_sig;
  unsigned char* msg;

  TypedData_Get_Struct(self, SchnorrSignature, &SchnorrSignature_DataType, schnorr_sig);
  TypedData_Get_Struct(in_xonly_pubkey, XOnlyPublicKey, &XOnlyPublicKey_DataType, xonly_pubkey);
  Check_Type(in_message, T_STRING);

  msg = (unsigned char*)StringValuePtr(in_message);
  if (secp256k1_schnorrsig_verify(secp256k1_context_static, schnorr_sig->sig, msg, RSTRING_LEN(in_message), &xonly_pubkey->pubkey) != 1)
  {
    return Qfalse;
  }

  return Qtrue;
}

static VALUE
SchnorrSignature_equals(VALUE self, VALUE other)
{
  SchnorrSignature *lhs;
  SchnorrSignature *rhs;

  TypedData_Get_Struct(self, SchnorrSignature, &SchnorrSignature_DataType, lhs);
  TypedData_Get_Struct(other, SchnorrSignature, &SchnorrSignature_DataType, rhs);

  if (memcmp(lhs->sig, rhs->sig, SCHNORR_SIG_SIZE_BYTES) == 0)
  {
    return Qtrue;
  }

  return Qfalse;
}

#endif // HAVE_SECP256K1_SCHNORRSIG_H

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
 * @param context_randomization_bytes [String,nil] (Optional) 32 bytes of
 *   random data used to randomize the context. If omitted then the
 *   context remains unrandomized. It is recommended that you provide this
 *   argument.
 * @return [Secp256k1::Context] 
 * @raise [Secp256k1::Error] if context randomization fails.
 */
static VALUE
Context_initialize(int argc, const VALUE* argv, VALUE self)
{
  Context *context;
  unsigned char *seed32;
  VALUE context_randomization_bytes;
  VALUE opts;
  static ID kwarg_ids;

  context_randomization_bytes = Qnil;
  if (!kwarg_ids)
  {
    CONST_ID(kwarg_ids, "context_randomization_bytes");
  }

  TypedData_Get_Struct(self, Context, &Context_DataType, context);

  context->ctx = secp256k1_context_create(
    SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
  );

  // Handle optional second argument containing random bytes to use for
  // randomization. We pass ":" to rb_scan_args to say that we expect keyword
  // arguments. We then parse the opts result of the scan in order to grab
  // context_randomization_bytes from the hash.
  rb_scan_args(argc, argv, ":", &opts);
  rb_get_kwargs(opts, &kwarg_ids, 0, 1, &context_randomization_bytes);

  // We need this check because rb_get_kwargs will set the result to Qundef if
  // the keyword argument is not provided. This lets us use the NIL_P
  // predicate.
  if (context_randomization_bytes == Qundef)
  {
    context_randomization_bytes = Qnil;
  }

  if (!NIL_P(context_randomization_bytes)) // Random bytes given
  {
    Check_Type(context_randomization_bytes, T_STRING);
    if (RSTRING_LEN(context_randomization_bytes) != 32)
    {
      rb_raise(
        Secp256k1_Error_class,
        "context_randomization_bytes must be 32 bytes in length"
      );
    }

    seed32 = (unsigned char*)StringValuePtr(context_randomization_bytes);

    // Randomize the context at initialization time rather than before calls so
    // the same context can be used across threads safely.
    if (secp256k1_context_randomize(context->ctx, seed32) != 1)
    {
      rb_raise(
        Secp256k1_Error_class,
        "context randomization failed"
      );
    }
  }

  return self;
}

/**
 * Converts binary private key data into a new key pair.
 *
 * @param in_private_key_data [String] binary private key data
 * @return [Secp256k1::KeyPair] key pair initialized from the private key data.
 * @raise [Secp256k1::Error] if the private key data is invalid or key derivation
 *   fails.
 */
static VALUE
Context_key_pair_from_private_key(VALUE self, VALUE in_private_key_data)
{
  Context *context;
  VALUE result;
  KeyPair *keypair;
  unsigned char *private_key_data;

  Check_Type(in_private_key_data, T_STRING);
  TypedData_Get_Struct(self, Context, &Context_DataType, context);

  if (RSTRING_LEN(in_private_key_data) != 32)
  {
    rb_raise(Secp256k1_Error_class, "private key data must be 32 bytes in length");
    return Qnil;
  }

  result = KeyPair_alloc(Secp256k1_KeyPair_class);
  TypedData_Get_Struct(result, KeyPair, &KeyPair_DataType, keypair);

  private_key_data = (unsigned char*)StringValuePtr(in_private_key_data);

  if (secp256k1_keypair_create(context->ctx, &keypair->keypair, private_key_data) == 0)
  {
    rb_raise(Secp256k1_Error_class, "invalid secret when attempting to create keypair");
  }

  return result;
}

/**
 * Computes the ECDSA signature of the data using the secp256k1 elliptic curve.
 *
 * @param in_private_key [Secp256k1::PrivateKey] private key to use for
 *   signing.
 * @param in_hash32 [String] 32-byte binary string with SHA-256 hash of data.
 * @return [Secp256k1::Signature] signature resulting from signing data.
 * @raise [Secp256k1::Error] if hash is not 32-bytes in length or signature
 *   computation fails.
 */
static VALUE
Context_sign(VALUE self, VALUE in_private_key, VALUE in_hash32)
{
  unsigned char *hash32;
  PrivateKey *private_key;
  Context *context;
  Signature *signature;
  VALUE signature_result;

  Check_Type(in_hash32, T_STRING);

  if (RSTRING_LEN(in_hash32) != 32)
  {
    rb_raise(Secp256k1_Error_class, "in_hash32 is not 32 bytes in length");
    return Qnil;
  }

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(in_private_key, PrivateKey, &PrivateKey_DataType, private_key);
  hash32 = (unsigned char*)StringValuePtr(in_hash32);

  signature_result = Signature_alloc(Secp256k1_Signature_class);
  TypedData_Get_Struct(signature_result, Signature, &Signature_DataType, signature);
 
  // Attempt to sign the hash of the given data
  if (SUCCESS(SignData(context->ctx,
                       hash32,
                       private_key->data,
                       &(signature->sig))))
  {
    return signature_result;
  }

  rb_raise(Secp256k1_Error_class, "unable to compute signature");
  return Qnil;
}

/**
 * Computes the tagged hash as defined in BIP-340.
 *
 * @param in_tag [String] tag value included in the hash.
 * @param in_message [String] message to be hashed.
 * @return [String] 32-byte binary hash.
 */
static VALUE
Context_tagged_sha256(VALUE self, VALUE in_tag, VALUE in_message)
{
  Context *context;
  unsigned char* tag;
  unsigned char* msg;
  unsigned char hash32[32];

  Check_Type(in_tag, T_STRING);
  Check_Type(in_message, T_STRING);

  TypedData_Get_Struct(self, Context, &Context_DataType, context);

  tag = (unsigned char*)StringValuePtr(in_tag);
  msg = (unsigned char*)StringValuePtr(in_message);

  if (secp256k1_tagged_sha256(context->ctx, hash32, tag, RSTRING_LEN(in_tag), msg, RSTRING_LEN(in_message)) != 1)
  {
    rb_raise(Secp256k1_Error_class, "failed to compute tagged SHA256");
    return Qnil;
  }

  return rb_str_new((char*)hash32, 32);
}

/**
 * Verifies that signature matches public key and data.
 *
 * @param in_signature [Secp256k1::Signature] signature to be verified.
 * @param in_pubkey [Secp256k1::PublicKey] public key to verify signature
 *   against.
 * @param in_hash32 [String] 32-byte binary string containing SHA-256 hash of
 *   data.
 * @return [Boolean] True if the signature is valid, false otherwise.
 * @raise [Secp256k1::Error] if hash is not 32-bytes in length.
 */
static VALUE
Context_verify(VALUE self, VALUE in_signature, VALUE in_pubkey, VALUE in_hash32)
{
  Context *context;
  PublicKey *public_key;
  Signature *signature;
  unsigned char *hash32;

  Check_Type(in_hash32, T_STRING);

  if (RSTRING_LEN(in_hash32) != 32)
  {
    rb_raise(Secp256k1_Error_class, "in_hash32 is not 32-bytes in length");
  }

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(in_pubkey, PublicKey, &PublicKey_DataType, public_key);
  TypedData_Get_Struct(in_signature, Signature, &Signature_DataType, signature);

  hash32 = (unsigned char*)StringValuePtr(in_hash32);
  
  if (secp256k1_ecdsa_verify(context->ctx,
                             &(signature->sig),
                             hash32,
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
 * @param in_hash32 [String] 32-byte binary string with SHA-256 hash of data.
 * @return [Secp256k1::RecoverableSignature] recoverable signature produced by
 *   signing the SHA-256 hash `in_hash32` with `in_private_key`.
 * @raise [Secp256k1::Error] if the hash is not 32 bytes or signature could not
 *   be computed.
 */
static VALUE
Context_sign_recoverable(VALUE self, VALUE in_private_key, VALUE in_hash32)
{
  Context *context;
  PrivateKey *private_key;
  RecoverableSignature *recoverable_signature;
  unsigned char *hash32;
  VALUE result;

  Check_Type(in_hash32, T_STRING);
  if (RSTRING_LEN(in_hash32) != 32)
  {
    rb_raise(Secp256k1_Error_class, "in_hash32 is not 32 bytes in length");
    return Qnil;
  }

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(
    in_private_key, PrivateKey, &PrivateKey_DataType, private_key
  );
  hash32 = (unsigned char*)StringValuePtr(in_hash32);

  result = RecoverableSignature_alloc(Secp256k1_RecoverableSignature_class);
  TypedData_Get_Struct(
    result,
    RecoverableSignature,
    &RecoverableSignature_DataType,
    recoverable_signature
  );

  if (SUCCESS(RecoverableSignData(context->ctx,
                                  hash32,
                                  private_key->data,
                                  &(recoverable_signature->sig))))
  {
    recoverable_signature->ctx = secp256k1_context_clone(context->ctx);
    return result;
  }

  rb_raise(Secp256k1_Error_class, "unable to compute recoverable signature");
  return Qnil;
}

/**
 * Loads recoverable signature from compact representation and recovery ID.
 *
 * @param in_compact_sig [String] binary string containing compact signature
 *   data.
 * @param in_recovery_id [Integer] recovery ID (range [0, 3])
 * @return [Secp256k1::RecoverableSignature] signature parsed from data.
 * @raise [Secp256k1::DeserializationError] if signature data or recovery ID is
 *   invalid.
 * @raise [Secp256k1::Error] if compact signature is not 64 bytes or recovery ID
 *   is not in range [0, 3].
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
    rb_raise(Secp256k1_Error_class, "compact signature is not 64 bytes");
    return Qnil;
  }

  if (recovery_id < 0 || recovery_id > 3)
  {
    rb_raise(Secp256k1_Error_class, "invalid recovery ID, must be in range [0, 3]");
    return Qnil;
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
  
  rb_raise(Secp256k1_DeserializationError_class, "unable to parse recoverable signature");
  return Qnil;
}

#endif // HAVE_SECP256K1_RECOVERY_H

// Context EC Diffie-Hellman methods
#ifdef HAVE_SECP256K1_ECDH_H

/**
 * Compute EC Diffie-Hellman secret in constant time.
 *
 * Creates a new shared secret from public_key and private_key.
 *
 * @param point [Secp256k1::PublicKey] public-key representing ECDH point.
 * @param scalar [Secp256k1::PrivateKey] private-key representing ECDH scalar.
 * @return [Secp256k1::SharedSecret] shared secret
 * @raise [Secp256k1::Error] If scalar was invalid (zero or caused overflow).
 */
static VALUE
Context_ecdh(VALUE self, VALUE point, VALUE scalar)
{
  Context *context;
  PublicKey *public_key;
  PrivateKey *private_key;
  SharedSecret *shared_secret;
  VALUE result;

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(point, PublicKey, &PublicKey_DataType, public_key);
  TypedData_Get_Struct(scalar, PrivateKey, &PrivateKey_DataType, private_key);

  result = SharedSecret_alloc(Secp256k1_SharedSecret_class);
  TypedData_Get_Struct(
    result, SharedSecret, &SharedSecret_DataType, shared_secret
  );

  if (secp256k1_ecdh(context->ctx,
                     shared_secret->data,
                     &(public_key->pubkey),
                     (unsigned char*)private_key->data,
                     NULL,
                     NULL) != 1)
  {
    rb_raise(Secp256k1_Error_class, "invalid scalar provided to ecdh");
    return Qnil;
  }

  rb_iv_set(result, "@data", rb_str_new((char*)shared_secret->data, 32));

  return result;
}

#endif // HAVE_SECP256K1_ECDH_H

#ifdef HAVE_SECP256K1_SCHNORRSIG_H

static VALUE
Context_sign_schnorr_custom(VALUE self, VALUE in_keypair, VALUE in_message, VALUE in_auxrand)
{
  Context* context;
  KeyPair* keypair;
  SchnorrSignature* schnorr_sig;
  unsigned char* msg;
  unsigned char* auxrand;
  unsigned char sig[64];
  VALUE result;

  TypedData_Get_Struct(self, Context, &Context_DataType, context);
  TypedData_Get_Struct(in_keypair, KeyPair, &KeyPair_DataType, keypair);

  Check_Type(in_message, T_STRING);
  if (RSTRING_LEN(in_message) != 32)
  {
    rb_raise(Secp256k1_Error_class, "schnorr signing message must be 32-bytes in length");
    return Qnil;
  }

  if (!NIL_P(in_auxrand))
  {
    Check_Type(in_auxrand, T_STRING);
    if (RSTRING_LEN(in_auxrand) != 32)
    {
      rb_raise(Secp256k1_Error_class, "schnorr signing auxrand must be 32-bytes in length");
      return Qnil;
    }
  }

  msg = (unsigned char*)StringValuePtr(in_message);
  auxrand = (unsigned char*)StringValuePtr(in_auxrand);

  if (secp256k1_schnorrsig_sign32(context->ctx, sig, msg, &keypair->keypair, auxrand) != 1)
  {
    rb_raise(Secp256k1_Error_class, "schnorr signing failed");
    return Qnil;
  }

  result = SchnorrSignature_alloc(Secp256k1_SchnorrSignature_class);
  TypedData_Get_Struct(result, SchnorrSignature, &SchnorrSignature_DataType, schnorr_sig);
  memcpy(schnorr_sig->sig, sig, SCHNORR_SIG_SIZE_BYTES);

  return result;
}

#endif // HAVE_SECP256K1_SCHNORRSIG_H

//
// Secp256k1 module methods
//

/**
 * Indicates whether or not the libsecp256k1 recovery module is installed.
 *
 * @return [Boolean] true if libsecp256k1 was built with the recovery module,
 *   false otherwise.
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

/**
 * Indicates whether or not libsecp256k1 EC Diffie-Hellman module is installed.
 *
 * @return [Boolean] true if libsecp256k1 was build with the ECDH module, false
 *   otherwise.
 */
static VALUE
Secp256k1_have_ecdh(VALUE module)
{
#ifdef HAVE_SECP256K1_ECDH_H
  return Qtrue;
#else // HAVE_SECP256K1_ECDH_H
  return Qfalse;
#endif // HAVE_SECP256K1_ECDH_H
}

/**
 * Indicates whether or not libsecp256k1 Schnorr signature module is installed.
 *
 * @return [Boolean]
 */
static VALUE
Secp256k1_have_schnorr(VALUE module)
{
#ifdef HAVE_SECP256K1_SCHNORRSIG_H
  return Qtrue;
#else
  return Qfalse;
#endif
}

//
// Library initialization
//

void Init_rbsecp256k1(void)
{
  // Perform selftest to ensure secp256k1_context_static is valid. This will
  // cause the program to abort if the selftest fails.
  secp256k1_selftest();

  // Secp256k1
  Secp256k1_module = rb_define_module("Secp256k1");
  rb_define_singleton_method(
    Secp256k1_module,
    "have_recovery?",
    Secp256k1_have_recovery,
    0
  );
  rb_define_singleton_method(
    Secp256k1_module,
    "have_ecdh?",
    Secp256k1_have_ecdh,
    0
  );
  rb_define_singleton_method(
    Secp256k1_module,
    "have_schnorr?",
    Secp256k1_have_schnorr,
    0
  );

  // Secp256k1 exception hierarchy
  Secp256k1_Error_class = rb_define_class_under(
    Secp256k1_module, "Error", rb_eStandardError
  );
  Secp256k1_SerializationError_class = rb_define_class_under(
    Secp256k1_module, "SerializationError", Secp256k1_Error_class
  );
  Secp256k1_DeserializationError_class = rb_define_class_under(
    Secp256k1_module, "DeserializationError", Secp256k1_Error_class
  );

  // Secp256k1::Context
  Secp256k1_Context_class = rb_define_class_under(
    Secp256k1_module, "Context", rb_cObject
  );
  rb_undef_alloc_func(Secp256k1_Context_class);
  rb_define_alloc_func(Secp256k1_Context_class, Context_alloc);
  rb_define_method(Secp256k1_Context_class,
                   "initialize",
                   Context_initialize,
                   -1);
  rb_define_method(Secp256k1_Context_class,
                   "key_pair_from_private_key",
                   Context_key_pair_from_private_key,
                   1);
  rb_define_method(Secp256k1_Context_class,
                   "sign",
                   Context_sign,
                   2);
  rb_define_method(Secp256k1_Context_class,
                   "tagged_sha256",
                   Context_tagged_sha256,
                   2);
  rb_define_method(Secp256k1_Context_class,
                   "verify",
                   Context_verify,
                   3);

  // Secp256k1::KeyPair
  Secp256k1_KeyPair_class = rb_define_class_under(Secp256k1_module,
                                                  "KeyPair",
                                                  rb_cObject);
  rb_undef_alloc_func(Secp256k1_KeyPair_class);
  rb_define_alloc_func(Secp256k1_KeyPair_class, KeyPair_alloc);
  rb_define_method(Secp256k1_KeyPair_class, "public_key", KeyPair_public_key, 0);
  rb_define_method(Secp256k1_KeyPair_class, "private_key", KeyPair_private_key, 0);
  rb_define_method(Secp256k1_KeyPair_class, "xonly_public_key", KeyPair_xonly_public_key, 0);
  rb_define_method(Secp256k1_KeyPair_class, "==", KeyPair_equals, 1);

  // Secp256k1::PublicKey
  Secp256k1_PublicKey_class = rb_define_class_under(Secp256k1_module,
                                                    "PublicKey",
                                                    rb_cObject);
  rb_undef_alloc_func(Secp256k1_PublicKey_class);
  rb_define_alloc_func(Secp256k1_PublicKey_class, PublicKey_alloc);
  rb_define_method(Secp256k1_PublicKey_class,
                   "compressed",
                   PublicKey_compressed,
                   0);
  rb_define_method(Secp256k1_PublicKey_class,
                   "uncompressed",
                   PublicKey_uncompressed,
                   0);
  rb_define_method(Secp256k1_PublicKey_class,
                   "to_xonly",
                   PublicKey_to_xonly,
                   0);
  rb_define_singleton_method(
    Secp256k1_PublicKey_class,
    "from_data",
    PublicKey_from_data,
    1
  );
  rb_define_method(Secp256k1_PublicKey_class, "==", PublicKey_equals, 1);

  // Secp256k1::XOnlyPublicKey
  Secp256k1_XOnlyPublicKey_class = rb_define_class_under(Secp256k1_module,
                                                         "XOnlyPublicKey",
                                                         rb_cObject);

  rb_undef_alloc_func(Secp256k1_XOnlyPublicKey_class);
  rb_define_alloc_func(Secp256k1_XOnlyPublicKey_class, XOnlyPublicKey_alloc);
  rb_define_method(Secp256k1_XOnlyPublicKey_class,
                   "serialized",
                   XOnlyPublicKey_serialized,
                   0);
  rb_define_singleton_method(
    Secp256k1_XOnlyPublicKey_class,
    "from_data",
    XOnlyPublicKey_from_data,
    1);
  rb_define_method(Secp256k1_XOnlyPublicKey_class, "==", XOnlyPublicKey_equals, 1);

  // Secp256k1::PrivateKey
  Secp256k1_PrivateKey_class = rb_define_class_under(
    Secp256k1_module, "PrivateKey", rb_cObject
  );
  rb_undef_alloc_func(Secp256k1_PrivateKey_class);
  rb_define_alloc_func(Secp256k1_PrivateKey_class, PrivateKey_alloc);
  rb_define_method(Secp256k1_PrivateKey_class, "data", PrivateKey_data, 0);
  rb_define_method(Secp256k1_PrivateKey_class, "==", PrivateKey_equals, 1);
  rb_define_singleton_method(
    Secp256k1_PrivateKey_class,
    "from_data",
    PrivateKey_from_data,
    1
  );

  // Secp256k1::Signature
  Secp256k1_Signature_class = rb_define_class_under(Secp256k1_module,
                                                    "Signature",
                                                    rb_cObject);
  rb_undef_alloc_func(Secp256k1_Signature_class);
  rb_define_alloc_func(Secp256k1_Signature_class, Signature_alloc);
  rb_define_method(Secp256k1_Signature_class,
                   "der_encoded",
                   Signature_der_encoded,
                   0);
  rb_define_method(Secp256k1_Signature_class,
                   "compact",
                   Signature_compact,
                   0);
  rb_define_method(Secp256k1_Signature_class,
                   "normalized",
                   Signature_normalized,
                   0);
  rb_define_method(Secp256k1_Signature_class,
                   "==",
                   Signature_equals,
                   1);
  rb_define_singleton_method(
    Secp256k1_Signature_class,
    "from_compact",
    Signature_from_compact,
    1
  );
  rb_define_singleton_method(
    Secp256k1_Signature_class,
    "from_der_encoded",
    Signature_from_der_encoded,
    1
  );

#ifdef HAVE_SECP256K1_RECOVERY_H
  // Secp256k1::RecoverableSignature
  Secp256k1_RecoverableSignature_class = rb_define_class_under(
    Secp256k1_module,
    "RecoverableSignature",
    rb_cObject
  );
  rb_undef_alloc_func(Secp256k1_RecoverableSignature_class);
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
  rb_define_method(
    Secp256k1_RecoverableSignature_class,
    "==",
    RecoverableSignature_equals,
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

#ifdef HAVE_SECP256K1_ECDH_H
  Secp256k1_SharedSecret_class = rb_define_class_under(
    Secp256k1_module,
    "SharedSecret",
    rb_cObject
  );
  rb_undef_alloc_func(Secp256k1_SharedSecret_class);
  rb_define_alloc_func(Secp256k1_SharedSecret_class, SharedSecret_alloc);
  rb_define_attr(Secp256k1_SharedSecret_class, "data", 1, 0);

  // Context EC Diffie-Hellman methods
  rb_define_method(
    Secp256k1_Context_class,
    "ecdh",
    Context_ecdh,
    2
  );
#endif // HAVE_SECP256K1_ECDH_H

#ifdef HAVE_SECP256K1_SCHNORRSIG_H
  Secp256k1_SchnorrSignature_class = rb_define_class_under(
    Secp256k1_module,
    "SchnorrSignature",
    rb_cObject);
  rb_undef_alloc_func(Secp256k1_SchnorrSignature_class);
  rb_define_alloc_func(Secp256k1_SchnorrSignature_class, SchnorrSignature_alloc);
  rb_define_method(Secp256k1_SchnorrSignature_class, "serialized", SchnorrSignature_serialized, 0);
  rb_define_method(Secp256k1_SchnorrSignature_class, "verify", SchnorrSignature_verify, 2);
  rb_define_method(Secp256k1_SchnorrSignature_class, "==", SchnorrSignature_equals, 1);

  rb_define_singleton_method(
    Secp256k1_SchnorrSignature_class,
    "from_data",
    SchnorrSignature_from_data,
    1
  );

  rb_define_method(
    Secp256k1_Context_class,
    "sign_schnorr_custom",
    Context_sign_schnorr_custom,
    3);
#endif // HAVE_SECP256K1_SCHNORRSIG_H
}

//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020 Gokuyun Moscow Algorithm Lab
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to
//  deal in the Software without restriction, including without limitation the
//  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
//  sell copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//  IN THE SOFTWARE.
//---------------------------------------------------------------------------//

#include <filcrypto.hpp>

/// Compute the digest of a message
///
/// # Arguments
///
/// * `message_ptr` - pointer to a message byte array
/// * `message_len` - length of the byte array
fil_HashResponse *fil_hash(const uint8_t *message_ptr, size_t message_len) {
  // prep request
  let message = from_raw_parts(message_ptr, message_len);

  // call method
  let digest = hash_sig(message);

  // prep response
  std::array<std::uint8_t, DIGEST_BYTES> raw_digest;
  raw_digest.fill(0);
  raw_digest.copy_from_slice(digest.into_affine().into_compressed().as_ref());

  let response = types::fil_HashResponse{
    digest : fil_BLSDigest{inner : raw_digest},
  };

  Box::into_raw(Box::new (response))
}

/// Aggregate signatures together into a new signature
///
/// # Arguments
///
/// * `flattened_signatures_ptr` - pointer to a byte array containing signatures
/// * `flattened_signatures_len` - length of the byte array (multiple of
/// SIGNATURE_BYTES)
///
/// Returns `NULL` on error. Result must be freed using
/// `destroy_aggregate_response`.
fil_AggregateResponse *fil_aggregate(const uint8_t *flattened_signatures_ptr,
                                     size_t flattened_signatures_len) {
  // prep request
  let signatures = try_ffi !(
      from_raw_parts(flattened_signatures_ptr, flattened_signatures_len)
          .par_chunks(SIGNATURE_BYTES)
          .map(| item | {Signature::from_bytes(item)})
          .collect::<Result<Vec<_>, _>>(),
      std::ptr::null_mut());

  let mut raw_signature : [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];

  let aggregated = try_ffi !(aggregate_sig(&signatures), std::ptr::null_mut());
  aggregated.write_bytes(&mut raw_signature.as_mut()).expect("preallocated");

  let response = types::fil_AggregateResponse{
    signature : fil_BLSSignature{
      inner : raw_signature,
    },
  };

  Box::into_raw(Box::new (response))
}

/// Verify that a signature is the aggregated signature of hashes - pubkeys
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array
/// (SIGNATURE_BYTES long)
/// * `flattened_digests_ptr`     - pointer to a byte array containing digests
/// * `flattened_digests_len`     - length of the byte array (multiple of
/// DIGEST_BYTES)
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public
/// keys
/// * `flattened_public_keys_len` - length of the array
int fil_verify(const uint8_t *signature_ptr,
               const uint8_t *flattened_digests_ptr,
               size_t flattened_digests_len,
               const uint8_t *flattened_public_keys_ptr,
               size_t flattened_public_keys_len) {
  // prep request
  let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
  let signature = try_ffi !(Signature::from_bytes(raw_signature), 0);

  let raw_digests =
      from_raw_parts(flattened_digests_ptr, flattened_digests_len);
  let raw_public_keys =
      from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);

  if raw_digests
    .len() % DIGEST_BYTES != 0 { return 0; }
  if raw_public_keys
    .len() % PUBLIC_KEY_BYTES != 0 { return 0; }

  if raw_digests
    .len() / DIGEST_BYTES != raw_public_keys.len() / PUBLIC_KEY_BYTES {
      return 0;
    }

  let digests : Vec<_> = try_ffi !(
                    raw_digests.par_chunks(DIGEST_BYTES)
                        .map(| item
                             : &[u8] |
                                   {
                                     let mut digest = G2Compressed::empty();
                                     digest.as_mut().copy_from_slice(item);

                                     let affine : G2Affine =
                                                      digest.into_affine() ? ;
                                     let projective = affine.into_projective();
                                     Ok(projective)
                                   })
                        .collect::<Result<Vec<_>, GroupDecodingError>>(),
                    0);

  let public_keys
      : Vec<_> = try_ffi !(raw_public_keys.par_chunks(PUBLIC_KEY_BYTES)
                               .map(| item | {PublicKey::from_bytes(item)})
                               .collect::<Result<_, _>>(),
                           0);

  verify_sig(&signature, digests.as_slice(), public_keys.as_slice())
      as libc::c_int
}

/// Verify that a signature is the aggregated signature of the hhashed messages
///
/// # Arguments
///
/// * `signature_ptr`             - pointer to a signature byte array
/// (SIGNATURE_BYTES long)
/// * `messages_ptr`              - pointer to an array containing the pointers
/// to the messages
/// * `messages_sizes_ptr`        - pointer to an array containing the lengths
/// of the messages
/// * `messages_len`              - length of the two messages arrays
/// * `flattened_public_keys_ptr` - pointer to a byte array containing public
/// keys
/// * `flattened_public_keys_len` - length of the array
int fil_hash_verify(const uint8_t *signature_ptr,
                    const uint8_t *flattened_messages_ptr,
                    size_t flattened_messages_len,
                    const size_t *message_sizes_ptr, size_t message_sizes_len,
                    const uint8_t *flattened_public_keys_ptr,
                    size_t flattened_public_keys_len) {
  // prep request
  let raw_signature = from_raw_parts(signature_ptr, SIGNATURE_BYTES);
  let signature = try_ffi !(Signature::from_bytes(raw_signature), 0);

  let flattened =
      from_raw_parts(flattened_messages_ptr, flattened_messages_len);
  let chunk_sizes = from_raw_parts(message_sizes_ptr, message_sizes_len);

  // split the flattened message array into slices of individual messages to
  // be hashed
  let mut messages : Vec<&[u8]> = Vec::with_capacity(message_sizes_len);
  let mut offset = 0;
    for
      chunk_size in chunk_sizes.iter() {
        messages.push(&flattened[offset..offset + *chunk_size]);
        offset += *chunk_size
      }

    let raw_public_keys =
        from_raw_parts(flattened_public_keys_ptr, flattened_public_keys_len);

    if raw_public_keys
      .len() % PUBLIC_KEY_BYTES != 0 { return 0; }

    let digests : Vec<_> = messages.into_par_iter()
                               .map(| message
                                    : &[u8] | hash_sig(message))
                               .collect::<Vec<_>>();

    let public_keys
        : Vec<_> = try_ffi !(raw_public_keys.par_chunks(PUBLIC_KEY_BYTES)
                                 .map(| item | {PublicKey::from_bytes(item)})
                                 .collect::<Result<_, _>>(),
                             0);

    verify_sig(&signature, &digests, &public_keys) as libc::c_int
}

/// Generate a new private key
fil_PrivateKeyGenerateResponse *fil_private_key_generate(void) {
  let mut raw_private_key : [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
  PrivateKey::generate(&mut OsRng)
      .write_bytes(&mut raw_private_key.as_mut())
      .expect("preallocated");

  let response = types::fil_PrivateKeyGenerateResponse{
    private_key : fil_BLSPrivateKey{
      inner : raw_private_key,
    },
  };

  Box::into_raw(Box::new (response))
}

/// Generate a new private key with seed
///
/// **Warning**: Use this function only for testing or with very secure seeds
///
/// # Arguments
///
/// * `raw_seed` - a seed byte array with 32 bytes
///
/// Returns `NULL` when passed a NULL pointer.
fil_PrivateKeyGenerateResponse *
fil_private_key_generate_with_seed(fil_32ByteArray raw_seed) {
  let rng = &mut ChaChaRng::from_seed(raw_seed.inner);

  let mut raw_private_key : [u8; PRIVATE_KEY_BYTES] = [0; PRIVATE_KEY_BYTES];
  PrivateKey::generate(rng)
      .write_bytes(&mut raw_private_key.as_mut())
      .expect("preallocated");

  let response = types::fil_PrivateKeyGenerateResponse{
    private_key : fil_BLSPrivateKey{
      inner : raw_private_key,
    },
  };

  Box::into_raw(Box::new (response))
}

/// Sign a message with a private key and return the signature
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
/// * `message_ptr` - pointer to a message byte array
/// * `message_len` - length of the byte array
///
/// Returns `NULL` when passed invalid arguments.
fil_PrivateKeySignResponse *
fil_private_key_sign(const uint8_t *raw_private_key_ptr,
                     const uint8_t *message_ptr, size_t message_len) {
  // prep request
  let private_key_slice =
      from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
  let private_key = try_ffi !(PrivateKey::from_bytes(private_key_slice),
                              std::ptr::null_mut());
  let message = from_raw_parts(message_ptr, message_len);

  let mut raw_signature : [u8; SIGNATURE_BYTES] = [0; SIGNATURE_BYTES];
  PrivateKey::sign(&private_key, message)
      .write_bytes(&mut raw_signature.as_mut())
      .expect("preallocated");

  let response = types::fil_PrivateKeySignResponse{
    signature : fil_BLSSignature{
      inner : raw_signature,
    },
  };

  Box::into_raw(Box::new (response))
}

/// Generate the public key for a private key
///
/// # Arguments
///
/// * `raw_private_key_ptr` - pointer to a private key byte array
///
/// Returns `NULL` when passed invalid arguments.
fil_PrivateKeyPublicKeyResponse *
fil_private_key_public_key(const uint8_t *raw_private_key_ptr) {
  let private_key_slice =
      from_raw_parts(raw_private_key_ptr, PRIVATE_KEY_BYTES);
  let private_key = try_ffi !(PrivateKey::from_bytes(private_key_slice),
                              std::ptr::null_mut());

  let mut raw_public_key : [u8; PUBLIC_KEY_BYTES] = [0; PUBLIC_KEY_BYTES];
  private_key.public_key()
      .write_bytes(&mut raw_public_key.as_mut())
      .expect("preallocated");

  let response = types::fil_PrivateKeyPublicKeyResponse{
    public_key : fil_BLSPublicKey{
      inner : raw_public_key,
    },
  };

  Box::into_raw(Box::new (response))
}
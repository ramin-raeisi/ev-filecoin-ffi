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

#include <functional>
#include <string>

/// TODO: document
///
fil_WriteWithAlignmentResponse *
fil_write_with_alignment(fil_RegisteredSealProof registered_proof, int src_fd,
                         uint64_t src_size, int dst_fd,
                         const uint64_t *existing_piece_sizes_ptr,
                         size_t existing_piece_sizes_len){catch_panic_response(
    ||
    {
  init_log();

  info !("write_with_alignment: start");

  let mut response = fil_WriteWithAlignmentResponse::default();

  let piece_sizes
      : Vec<UnpaddedBytesAmount> =
            from_raw_parts(existing_piece_sizes_ptr, existing_piece_sizes_len)
                .iter()
                .map(| n | UnpaddedBytesAmount(*n))
                .collect();

  let n = UnpaddedBytesAmount(src_size);

  match filecoin_proofs_api::seal::add_piece(
      registered_proof.into(), FileDescriptorRef::new (src_fd),
      FileDescriptorRef::new (dst_fd), n, &piece_sizes, ) {
    Ok((info, written)) = > {
      response.comm_p = info.commitment;
      response.left_alignment_unpadded = (written - n).into();
      response.status_code = FCPResponseStatus::FCPNoError;
      response.total_write_unpadded = written.into();
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("write_with_alignment: finish");

  raw_ptr(response)
    })}

/// TODO: document
///
fil_WriteWithoutAlignmentResponse *fil_write_without_alignment(
    fil_RegisteredSealProof registered_proof, int src_fd, uint64_t src_size,
    int dst_fd){catch_panic_response(
    ||
    {
  init_log();

  info !("write_without_alignment: start");

  let mut response = fil_WriteWithoutAlignmentResponse::default();

  match filecoin_proofs_api::seal::write_and_preprocess(
      registered_proof.into(), FileDescriptorRef::new (src_fd),
      FileDescriptorRef::new (dst_fd), UnpaddedBytesAmount(src_size), ) {
    Ok((info, written)) = > {
      response.comm_p = info.commitment;
      response.status_code = FCPResponseStatus::FCPNoError;
      response.total_write_unpadded = written.into();
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("write_without_alignment: finish");

  raw_ptr(response)
    })}

fil_FauxRepResponse *fil_fauxrep(fil_RegisteredSealProof registered_proof,
                                 const char *cache_dir_path,
                                 const char *sealed_sector_path){
    catch_panic_response(
        ||
        {
  init_log();

  info !("fauxrep: start");

  let mut response : fil_FauxRepResponse = Default::default();

  let result = filecoin_proofs_api::seal::fauxrep(
      registered_proof.into(), c_str_to_pbuf(cache_dir_path),
      c_str_to_pbuf(sealed_sector_path), );

  match result {
    Ok(output) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.commitment = output;
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("fauxrep: finish");

  raw_ptr(response)
        })}

fil_FauxRepResponse *fil_fauxrep2(fil_RegisteredSealProof registered_proof,
                                  const char *cache_dir_path,
                                  const char *existing_p_aux_path){
    catch_panic_response(
        ||
        {
  init_log();

  info !("fauxrep2: start");

  let mut response : fil_FauxRepResponse = Default::default();

  let result = filecoin_proofs_api::seal::fauxrep2(
      registered_proof.into(), c_str_to_pbuf(cache_dir_path),
      c_str_to_pbuf(existing_p_aux_path), );

  match result {
    Ok(output) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.commitment = output;
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("fauxrep2: finish");

  raw_ptr(response)
        })}

/// TODO: document
///
fil_SealPreCommitPhase1Response *fil_seal_pre_commit_phase1(
    fil_RegisteredSealProof registered_proof, const char *cache_dir_path,
    const char *staged_sector_path, const char *sealed_sector_path,
    uint64_t sector_id, fil_32ByteArray prover_id, fil_32ByteArray ticket,
    const fil_PublicPieceInfo *pieces_ptr,
    size_t pieces_len){catch_panic_response(
    ||
    {
  init_log();

  info !("seal_pre_commit_phase1: start");

  let public_pieces : Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
                                           .iter()
                                           .cloned()
                                           .map(Into::into)
                                           .collect();

  let mut response : fil_SealPreCommitPhase1Response = Default::default();

  let result =
      filecoin_proofs_api::seal::seal_pre_commit_phase1(
          registered_proof.into(), c_str_to_pbuf(cache_dir_path),
          c_str_to_pbuf(staged_sector_path), c_str_to_pbuf(sealed_sector_path),
          prover_id.inner, SectorId::from(sector_id), ticket.inner,
          &public_pieces, )
          .and_then(| output | serde_json::to_vec(&output).map_err(Into::into));

  match result {
    Ok(output) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.seal_pre_commit_phase1_output_ptr = output.as_ptr();
      response.seal_pre_commit_phase1_output_len = output.len();
      mem::forget(output);
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("seal_pre_commit_phase1: finish");

  raw_ptr(response)
    })}

/// TODO: document
///
fil_SealPreCommitPhase2Response *fil_seal_pre_commit_phase2(
    const uint8_t *seal_pre_commit_phase1_output_ptr,
    size_t seal_pre_commit_phase1_output_len, const char *cache_dir_path,
    const char *sealed_sector_path){catch_panic_response(
    ||
    {
  init_log();

  info !("seal_pre_commit_phase2: start");

  let mut response : fil_SealPreCommitPhase2Response = Default::default();

  let phase_1_output = serde_json::from_slice(
                           from_raw_parts(seal_pre_commit_phase1_output_ptr,
                                          seal_pre_commit_phase1_output_len, ))
                           .map_err(Into::into);

  let result = phase_1_output.and_then(
      | o |
      {filecoin_proofs_api::seal::seal_pre_commit_phase2::<PathBuf, PathBuf>(
          o, c_str_to_pbuf(cache_dir_path),
          c_str_to_pbuf(sealed_sector_path), )});

  match result {
    Ok(output) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.comm_r = output.comm_r;
      response.comm_d = output.comm_d;
      response.registered_proof = output.registered_proof.into();
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("seal_pre_commit_phase2: finish");

  raw_ptr(response)
    })}

/// TODO: document
///
fil_SealCommitPhase1Response *fil_seal_commit_phase1(
    fil_RegisteredSealProof registered_proof, fil_32ByteArray comm_r,
    fil_32ByteArray comm_d, const char *cache_dir_path,
    const char *replica_path, uint64_t sector_id, fil_32ByteArray prover_id,
    fil_32ByteArray ticket, fil_32ByteArray seed,
    const fil_PublicPieceInfo *pieces_ptr, size_t pieces_len) {
  catch_panic_response(|| {
  init_log();

  info !("seal_commit_phase1: start");

  let mut response = fil_SealCommitPhase1Response::default();

  let spcp2o = SealPreCommitPhase2Output{
    registered_proof : registered_proof.into(),
    comm_r : comm_r.inner,
    comm_d : comm_d.inner,
  };

  let public_pieces : Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
                                           .iter()
                                           .cloned()
                                           .map(Into::into)
                                           .collect();

  let result = filecoin_proofs_api::seal::seal_commit_phase1(
      c_str_to_pbuf(cache_dir_path), c_str_to_pbuf(replica_path),
      prover_id.inner, SectorId::from(sector_id), ticket.inner, seed.inner,
      spcp2o, &public_pieces, );

  match result.and_then(| output |
                        serde_json::to_vec(&output).map_err(Into::into)) {
    Ok(output) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.seal_commit_phase1_output_ptr = output.as_ptr();
      response.seal_commit_phase1_output_len = output.len();
      mem::forget(output);
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("seal_commit_phase1: finish");

  raw_ptr(response)
  })
}

fil_SealCommitPhase2Response *fil_seal_commit_phase2(const uint8_t *seal_commit_phase1_output_ptr,
                                                     size_t seal_commit_phase1_output_len,
                                                     uint64_t sector_id,
                                                     fil_32ByteArray prover_id) {
  catch_panic_response(|| {
  init_log();

  info !("seal_commit_phase2: start");

  let mut response = fil_SealCommitPhase2Response::default();

  let scp1o =
      serde_json::from_slice(from_raw_parts(seal_commit_phase1_output_ptr,
                                            seal_commit_phase1_output_len, ))
          .map_err(Into::into);

  let result =
      scp1o.and_then(| o |
                     {filecoin_proofs_api::seal::seal_commit_phase2(
                         o, prover_id.inner, SectorId::from(sector_id), )});

  match result {
    Ok(output) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.proof_ptr = output.proof.as_ptr();
      response.proof_len = output.proof.len();
      mem::forget(output.proof);
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("seal_commit_phase2: finish");

  raw_ptr(response)
  })
}

/// TODO: document
fil_UnsealRangeResponse *fil_unseal_range(fil_RegisteredSealProof registered_proof,
                                          const char *cache_dir_path,
                                          int sealed_sector_fd_raw,
                                          int unseal_output_fd_raw,
                                          uint64_t sector_id,
                                          fil_32ByteArray prover_id,
                                          fil_32ByteArray ticket,
                                          fil_32ByteArray comm_d,
                                          uint64_t unpadded_byte_index,
                                          uint64_t unpadded_bytes_amount) {
    catch_panic_response(|| {
  init_log();

  info !("unseal_range: start");

  use std::os::unix::io::{FromRawFd, IntoRawFd};

  let mut sealed_sector = std::fs::File::from_raw_fd(sealed_sector_fd_raw);
  let mut unseal_output = std::fs::File::from_raw_fd(unseal_output_fd_raw);

  let result = filecoin_proofs_api::seal::unseal_range(
      registered_proof.into(), c_str_to_pbuf(cache_dir_path),
      &mut sealed_sector, &mut unseal_output, prover_id.inner,
      SectorId::from(sector_id), comm_d.inner, ticket.inner,
      UnpaddedByteIndex(unpadded_byte_index),
      UnpaddedBytesAmount(unpadded_bytes_amount), );

  // keep all file descriptors alive until unseal_range returns
  let _ = sealed_sector.into_raw_fd();
  let _ = unseal_output.into_raw_fd();

  let mut response = fil_UnsealRangeResponse::default();

  match result{Ok(_) = > {response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
  response.status_code = FCPResponseStatus::FCPUnclassifiedError;
  response.error_msg = rust_str_to_c_str(format !("{:?}", err));
            }
};

info !("unseal_range: finish");

raw_ptr(response)
})
}

/// Verifies the output of seal.
///
fil_VerifySealResponse *
fil_verify_seal(fil_RegisteredSealProof registered_proof,
                fil_32ByteArray comm_r, fil_32ByteArray comm_d,
                fil_32ByteArray prover_id, fil_32ByteArray ticket,
                fil_32ByteArray seed, uint64_t sector_id,
                const uint8_t *proof_ptr, size_t proof_len) {
    catch_panic_response(|| {
  init_log();

  info !("verify_seal: start");

  let mut proof_bytes : Vec<u8> = vec ![0; proof_len];
  proof_bytes.clone_from_slice(from_raw_parts(proof_ptr, proof_len));

  let result = filecoin_proofs_api::seal::verify_seal(
      registered_proof.into(), comm_r.inner, comm_d.inner, prover_id.inner,
      SectorId::from(sector_id), ticket.inner, seed.inner, &proof_bytes, );

  let mut response = fil_VerifySealResponse::default();

  match result{Ok(true) =
                   > {response.status_code = FCPResponseStatus::FCPNoError;
  response.is_valid = true;
            }
            Ok(false) => {
  response.status_code = FCPResponseStatus::FCPNoError;
  response.is_valid = false;
            }
            Err(err) => {
  response.status_code = FCPResponseStatus::FCPUnclassifiedError;
  response.error_msg = rust_str_to_c_str(format !("{:?}", err));
            }
};

info !("verify_seal: finish");

raw_ptr(response)
})
}

/// Verifies that a proof-of-spacetime is valid.
fil_VerifyWinningPoStResponse *
fil_verify_winning_post(fil_32ByteArray randomness,
                        const fil_PublicReplicaInfo *replicas_ptr,
                        size_t replicas_len, const fil_PoStProof *proofs_ptr,
                        size_t proofs_len, fil_32ByteArray prover_id) {
    catch_panic_response(|| {
  init_log();

  info !("verify_winning_post: start");

  let mut response = fil_VerifyWinningPoStResponse::default();

  let convert =
      super::helpers::to_public_replica_info_map(replicas_ptr, replicas_len);

  let result = convert.and_then(| replicas | {
    let post_proofs = c_to_rust_post_proofs(proofs_ptr, proofs_len) ? ;
    let proofs
        : Vec<u8> =
              post_proofs.iter().flat_map(| pp | pp.clone().proof).collect();

    filecoin_proofs_api::post::verify_winning_post(&randomness.inner, &proofs,
                                                   &replicas, prover_id.inner, )
  });

  match result{Ok(is_valid) =
                   > {response.status_code = FCPResponseStatus::FCPNoError;
  response.is_valid = is_valid;
            }
            Err(err) => {
  response.status_code = FCPResponseStatus::FCPUnclassifiedError;
  response.error_msg = rust_str_to_c_str(format !("{:?}", err));
            }
};

info !("verify_winning_post: {}", "finish");
raw_ptr(response)
})
}

/// TODO: document
///
fil_GenerateWindowPoStResponse *
fil_generate_window_post(fil_32ByteArray randomness,
                         const fil_PrivateReplicaInfo *replicas_ptr,
                         size_t replicas_len, fil_32ByteArray prover_id) {
  catch_panic_response(|| {
  init_log();

  info !("generate_window_post: start");

  let mut response = fil_GenerateWindowPoStResponse::default();

  let result = to_private_replica_info_map(replicas_ptr, replicas_len)
                   .and_then(| rs |
                             {filecoin_proofs_api::post::generate_window_post(
                                 &randomness.inner, &rs, prover_id.inner)});

  match result {
    Ok(output) = > {
      let mapped : Vec<fil_PoStProof> =
                       output.iter()
                           .cloned()
                           .map(| (t, proof) |
                                {
                                  let out = fil_PoStProof{
                                    registered_proof : (t).into(),
                                    proof_len : proof.len(),
                                    proof_ptr : proof.as_ptr(),
                                  };

                                  mem::forget(proof);

                                  out
                                })
                           .collect();

      response.status_code = FCPResponseStatus::FCPNoError;
      response.proofs_ptr = mapped.as_ptr();
      response.proofs_len = mapped.len();
      mem::forget(mapped);
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("generate_window_post: finish");

  raw_ptr(response)
  })
}

/// Verifies that a proof-of-spacetime is valid.
fil_VerifyWindowPoStResponse *fil_verify_window_post(fil_32ByteArray randomness,
                                                     const fil_PublicReplicaInfo *replicas_ptr,
                                                     size_t replicas_len,
                                                     const fil_PoStProof *proofs_ptr,
                                                     size_t proofs_len,
                                                     fil_32ByteArray prover_id) {
    catch_panic_response(|| {
  init_log();

  info !("verify_window_post: start");

  let mut response = fil_VerifyWindowPoStResponse::default();

  let convert =
      super::helpers::to_public_replica_info_map(replicas_ptr, replicas_len);

  let result = convert.and_then(| replicas | {
    let post_proofs = c_to_rust_post_proofs(proofs_ptr, proofs_len) ? ;

    let proofs : Vec<(RegisteredPoStProof, &[u8])> =
                     post_proofs.iter()
                         .map(| x | (x.registered_proof, x.proof.as_ref()))
                         .collect();

    filecoin_proofs_api::post::verify_window_post(&randomness.inner, &proofs,
                                                  &replicas, prover_id.inner, )
  });

  match result{Ok(is_valid) =
                   > {response.status_code = FCPResponseStatus::FCPNoError;
  response.is_valid = is_valid;
            }
            Err(err) => {
  response.status_code = FCPResponseStatus::FCPUnclassifiedError;
  response.error_msg = rust_str_to_c_str(format !("{:?}", err));
            }
};

info !("verify_window_post: {}", "finish");
raw_ptr(response)
})
}

/// Returns the merkle root for a piece after piece padding and alignment.
/// The caller is responsible for closing the passed in file descriptor.
fil_GeneratePieceCommitmentResponse *
fil_generate_piece_commitment(fil_RegisteredSealProof registered_proof,
                              int piece_fd_raw, uint64_t unpadded_piece_size){
    catch_panic_response(
        ||
        {
  init_log();

  use std::os::unix::io::{FromRawFd, IntoRawFd};

  let mut piece_file = std::fs::File::from_raw_fd(piece_fd_raw);

  let unpadded_piece_size = UnpaddedBytesAmount(unpadded_piece_size);
  let result = filecoin_proofs_api::seal::generate_piece_commitment(
      registered_proof.into(), &mut piece_file, unpadded_piece_size, );

  // avoid dropping the File which closes it
  let _ = piece_file.into_raw_fd();

  let mut response = fil_GeneratePieceCommitmentResponse::default();

  match result {
    Ok(meta) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.comm_p = meta.commitment;
      response.num_bytes_aligned = meta.size.into();
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  raw_ptr(response)
        })}

/// Returns the merkle root for a sector containing the provided pieces.
fil_GenerateDataCommitmentResponse *fil_generate_data_commitment(
    fil_RegisteredSealProof registered_proof,
    const fil_PublicPieceInfo *pieces_ptr,
    size_t pieces_len){catch_panic_response(
    ||
    {
  init_log();

  info !("generate_data_commitment: start");

  let public_pieces : Vec<PieceInfo> = from_raw_parts(pieces_ptr, pieces_len)
                                           .iter()
                                           .cloned()
                                           .map(Into::into)
                                           .collect();

  let result = filecoin_proofs_api::seal::compute_comm_d(
      registered_proof.into(), &public_pieces);

  let mut response = fil_GenerateDataCommitmentResponse::default();

  match result {
    Ok(commitment) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.comm_d = commitment;
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  info !("generate_data_commitment: finish");

  raw_ptr(response)
    })}

fil_ClearCacheResponse *fil_clear_cache(uint64_t sector_size,
                                        const char *cache_dir_path) {
    catch_panic_response(|| {
  init_log();

  let result = filecoin_proofs_api::seal::clear_cache(
      sector_size, &c_str_to_pbuf(cache_dir_path));

  let mut response = fil_ClearCacheResponse::default();

  match result{Ok(_) = > {response.status_code = FCPResponseStatus::FCPNoError;
            }
            Err(err) => {
  response.status_code = FCPResponseStatus::FCPUnclassifiedError;
  response.error_msg = rust_str_to_c_str(format !("{:?}", err));
            }
};

raw_ptr(response)
})
}

/// TODO: document
///
fil_GenerateWinningPoStSectorChallenge *
fil_generate_winning_post_sector_challenge(
    fil_RegisteredPoStProof registered_proof, fil_32ByteArray randomness,
    uint64_t sector_set_len, fil_32ByteArray prover_id){catch_panic_response(
    ||
    {
      init_log();

      info !("generate_winning_post_sector_challenge: start");

      let mut response = fil_GenerateWinningPoStSectorChallenge::default();

      let result =
          filecoin_proofs_api::post::generate_winning_post_sector_challenge(
              registered_proof.into(), &randomness.inner, sector_set_len,
              prover_id.inner, );

      match result {
        Ok(output) = > {
          let mapped : Vec<u64> = output.into_iter().map(u64::from).collect();

          response.status_code = FCPResponseStatus::FCPNoError;
          response.ids_ptr = mapped.as_ptr();
          response.ids_len = mapped.len();
          mem::forget(mapped);
        }
        Err(err) = > {
          response.status_code = FCPResponseStatus::FCPUnclassifiedError;
          response.error_msg = rust_str_to_c_str(format !("{:?}", err));
        }
      }

      info !("generate_winning_post_sector_challenge: finish");

      raw_ptr(response)
    })}

/// TODO: document
///
fil_GenerateWinningPoStResponse *fil_generate_winning_post(
    fil_32ByteArray randomness, const fil_PrivateReplicaInfo *replicas_ptr,
    size_t replicas_len, fil_32ByteArray prover_id) {
  catch_panic_response(|| {
    init_log();

    info !("generate_winning_post: start");

    let mut response = fil_GenerateWinningPoStResponse::default();

    let result =
        to_private_replica_info_map(replicas_ptr, replicas_len)
            .and_then(| rs |
                      {filecoin_proofs_api::post::generate_winning_post(
                          &randomness.inner, &rs, prover_id.inner, )});

    match result {
      Ok(output) = > {
        let mapped : Vec<fil_PoStProof> =
                         output.iter()
                             .cloned()
                             .map(| (t, proof) |
                                  {
                                    let out = fil_PoStProof{
                                      registered_proof : (t).into(),
                                      proof_len : proof.len(),
                                      proof_ptr : proof.as_ptr(),
                                    };

                                    mem::forget(proof);

                                    out
                                  })
                             .collect();

        response.status_code = FCPResponseStatus::FCPNoError;
        response.proofs_ptr = mapped.as_ptr();
        response.proofs_len = mapped.len();
        mem::forget(mapped);
      }
      Err(err) = > {
        response.status_code = FCPResponseStatus::FCPUnclassifiedError;
        response.error_msg = rust_str_to_c_str(format !("{:?}", err));
      }
    }

    info !("generate_winning_post: finish");

    raw_ptr(response)
  })
}

void fil_destroy_write_with_alignment_response(
    fil_WriteWithAlignmentResponse *ptr) {
  delete ptr;
}

void fil_destroy_write_without_alignment_response(
    fil_WriteWithoutAlignmentResponse *ptr) {
  delete ptr;
}

void fil_destroy_fauxrep_response(fil_FauxRepResponse *ptr) { delete ptr; }

void fil_destroy_seal_pre_commit_phase1_response(
    fil_SealPreCommitPhase1Response *ptr) {
  delete ptr;
}

void fil_destroy_seal_pre_commit_phase2_response(
    fil_SealPreCommitPhase2Response *ptr) {
  delete ptr;
}

void fil_destroy_seal_commit_phase1_response(
    fil_SealCommitPhase1Response *ptr) {
  delete ptr;
}

void fil_destroy_seal_commit_phase2_response(
    fil_SealCommitPhase2Response *ptr) {
  delete ptr;
}

void fil_destroy_unseal_range_response(fil_UnsealRangeResponse *ptr) {
  delete ptr;
}

void fil_destroy_generate_piece_commitment_response(
    fil_GeneratePieceCommitmentResponse *ptr) {
  delete ptr;
}

void fil_destroy_generate_data_commitment_response(
    fil_GenerateDataCommitmentResponse *ptr) {
  delete ptr;
}

void fil_destroy_string_response(fil_StringResponse *ptr) { delete ptr; }

/// Returns the number of user bytes that will fit into a staged sector.
///
uint64_t fil_get_max_user_bytes_per_staged_sector(
    fil_RegisteredSealProof registered_proof){
    u64::from(UnpaddedBytesAmount::from(
        RegisteredSealProof::from(registered_proof).sector_size(), ))}

/// Returns the CID of the Groth parameter file for sealing.
///
fil_StringResponse *fil_get_seal_params_cid(
    fil_RegisteredSealProof registered_proof){
    registered_seal_proof_accessor(registered_proof,
                                   RegisteredSealProof::params_cid)}

/// Returns the CID of the verifying key-file for verifying a seal proof.
///
fil_StringResponse *fil_get_seal_verifying_key_cid(
    fil_RegisteredSealProof registered_proof){
    registered_seal_proof_accessor(registered_proof,
                                   RegisteredSealProof::verifying_key_cid)}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when sealing.
///
fil_StringResponse *fil_get_seal_params_path(
    fil_RegisteredSealProof registered_proof){registered_seal_proof_accessor(
    registered_proof,
    | p |
        {p.cache_params_path().map(| pb | String::from(pb.to_string_lossy()))})}

/// Returns the path from which the proofs library expects to find the verifying
/// key-file used when verifying a seal proof.
///
fil_StringResponse *fil_get_seal_verifying_key_path(
    fil_RegisteredSealProof registered_proof){registered_seal_proof_accessor(
    registered_proof,
    | p |
        {p.cache_verifying_key_path().map(| pb |
                                          String::from(pb.to_string_lossy()))})}

/// Returns the identity of the circuit for the provided seal proof.
///
fil_StringResponse *fil_get_seal_circuit_identifier(
    fil_RegisteredSealProof registered_proof){
    registered_seal_proof_accessor(registered_proof,
                                   RegisteredSealProof::circuit_identifier)}

/// Returns the version of the provided seal proof type.
///
fil_StringResponse *fil_get_seal_version(
    fil_RegisteredSealProof registered_proof){
    registered_seal_proof_accessor(registered_proof,
                                   | p | Ok(format !("{:?}", p)))}

/// Returns the CID of the Groth parameter file for generating a PoSt.
///
fil_StringResponse *fil_get_post_params_cid(
    fil_RegisteredPoStProof registered_proof){
    registered_post_proof_accessor(registered_proof,
                                   RegisteredPoStProof::params_cid)}

/// Returns the CID of the verifying key-file for verifying a PoSt proof.
///
fil_StringResponse *fil_get_post_verifying_key_cid(
    fil_RegisteredPoStProof registered_proof){
    registered_post_proof_accessor(registered_proof,
                                   RegisteredPoStProof::verifying_key_cid)}

/// Returns the path from which the proofs library expects to find the Groth
/// parameter file used when generating a PoSt.
///
fil_StringResponse *fil_get_post_params_path(
    fil_RegisteredPoStProof registered_proof){registered_post_proof_accessor(
    registered_proof,
    | p |
        {p.cache_params_path().map(| pb | String::from(pb.to_string_lossy()))})}

/// Returns the path from which the proofs library expects to find the verifying
/// key-file used when verifying a PoSt proof.
///
fil_StringResponse *fil_get_post_verifying_key_path(
    fil_RegisteredPoStProof registered_proof){registered_post_proof_accessor(
    registered_proof,
    | p |
        {p.cache_verifying_key_path().map(| pb |
                                          String::from(pb.to_string_lossy()))})}

/// Returns the identity of the circuit for the provided PoSt proof type.
///
fil_StringResponse *fil_get_post_circuit_identifier(
    fil_RegisteredPoStProof registered_proof){
    registered_post_proof_accessor(registered_proof,
                                   RegisteredPoStProof::circuit_identifier)}

/// Returns the version of the provided seal proof.
///
fil_StringResponse *fil_get_post_version(
    fil_RegisteredPoStProof registered_proof){
    registered_post_proof_accessor(registered_proof,
                                   | p | Ok(format !("{:?}", p)))}

fil_StringResponse *registered_seal_proof_accessor(
    fil_RegisteredSealProof registered_proof,
    const std::function<std::string(fil_RegisteredSealProof)> &op) {
  let mut response = fil_StringResponse::default();

  let rsp : RegisteredSealProof = registered_proof.into();

  match op(rsp) {
    Ok(s) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.string_val = rust_str_to_c_str(s);
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  raw_ptr(response)
}

fil_StringResponse *registered_post_proof_accessor(
    fil_RegisteredPoStProof registered_proof,
    std::function<std::string(fil_RegisteredPoStProof)> op) {
  let mut response = fil_StringResponse::default();

  let rsp : RegisteredPoStProof = registered_proof.into();

  match op(rsp) {
    Ok(s) = > {
      response.status_code = FCPResponseStatus::FCPNoError;
      response.string_val = rust_str_to_c_str(s);
    }
    Err(err) = > {
      response.status_code = FCPResponseStatus::FCPUnclassifiedError;
      response.error_msg = rust_str_to_c_str(format !("{:?}", err));
    }
  }

  raw_ptr(response)
}

/// Deallocates a VerifySealResponse.
///
void fil_destroy_verify_seal_response(fil_VerifySealResponse *ptr) {
  delete ptr;
}

void fil_destroy_finalize_ticket_response(fil_FinalizeTicketResponse *ptr) {
  delete ptr;
}

/// Deallocates a VerifyPoStResponse.
///
void fil_destroy_verify_winning_post_response(
    fil_VerifyWinningPoStResponse *ptr) {
  delete ptr;
}

void fil_destroy_verify_window_post_response(
    fil_VerifyWindowPoStResponse *ptr) {
  delete ptr;
}

void fil_destroy_generate_winning_post_response(
    fil_GenerateWinningPoStResponse *ptr) {
  delete ptr;
}

void fil_destroy_generate_window_post_response(
    fil_GenerateWindowPoStResponse *ptr) {
  delete ptr;
}

void fil_destroy_generate_winning_post_sector_challenge(
    fil_GenerateWinningPoStSectorChallenge *ptr) {
  delete ptr;
}

void fil_destroy_clear_cache_response(fil_ClearCacheResponse *ptr) {
  delete ptr;
}
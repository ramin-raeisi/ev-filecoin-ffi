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

#include <filcrypto.h>
/// HashResponse
void fil_destroy_hash_response(fil_HashResponse *ptr) { delete ptr; }

/// AggregateResponse
void fil_destroy_aggregate_response(fil_AggregateResponse *ptr) { delete ptr; }

/// PrivateKeyGenerateResponse
void fil_destroy_private_key_generate_response(
    fil_PrivateKeyGenerateResponse *ptr) {
  delete ptr;
}

/// PrivateKeySignResponse
void fil_destroy_private_key_sign_response(fil_PrivateKeySignResponse *ptr) {
  delete ptr;
}

/// PrivateKeyPublicKeyResponse
void fil_destroy_private_key_public_key_response(
    fil_PrivateKeyPublicKeyResponse *ptr) {
  delete ptr;
}

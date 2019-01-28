// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.#pragma once

#pragma once

#include <string>
#include <vector>

#include "bssl_wrapper/bssl_wrapper.h"

#define CBS_ASN1_TAG_SHIFT 24
#define CBS_ASN1_CONSTRUCTED (0x20u << CBS_ASN1_TAG_SHIFT)
#define CBS_ASN1_SEQUENCE (0x10u | CBS_ASN1_CONSTRUCTED)
#define CBS_ASN1_TAG_NUMBER_MASK ((1u << (5 + CBS_ASN1_TAG_SHIFT)) - 1)
#define CBS_ASN1_INTEGER 0x2u

namespace openssl {
namespace cbs {

class Cbs {
  public:
	Cbs(const uint8_t *data, size_t len);
	const uint8_t *data_;
	size_t len_;
};

int bn_cmp_word(BIGNUM *a, BN_ULONG b);
RSA* public_key_from_bytes(const uint8_t *in, size_t in_len);
RSA* parse_public_key(Cbs *cbs);
int cbs_get_asn1(Cbs *cbs, Cbs *out, unsigned tag_value, int skip_header);
int cbs_skip(Cbs *cbs, size_t len);
int cbs_get(Cbs *cbs, const uint8_t **p, size_t n);
int cbs_get_any_asn1_element(Cbs *cbs, Cbs *out, unsigned *out_tag, size_t *out_header_len, int ber_ok);
int cbs_get_u(Cbs *cbs, uint32_t *out, size_t len);
int cbs_get_bytes(Cbs *cbs, Cbs *out, size_t len);
void cbs_init(Cbs *cbs, const uint8_t *data, size_t len);
int cbs_get_u8(Cbs *cbs, uint8_t *out);
int parse_asn1_tag(Cbs *cbs, unsigned *out);
int bn_parse_asn1_unsigned(Cbs *cbs, BIGNUM *ret);
int parse_base128_integer(Cbs *cbs, uint64_t *out);
int parse_integer(Cbs *cbs, BIGNUM **out);




}  // namespace cbs
}  // namespace openssl

/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "cbs.h"

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

namespace openssl {
namespace cbs {

Cbs::Cbs(const uint8_t *data, size_t len) {
  data_ = data;
  len = len;
}

int bn_cmp_word(BIGNUM *a, BN_ULONG b) {
	  std::cerr << "!!!!!!!!!!!!!!!! bn_cmp_word \n";
  BIGNUM* b_bn = BN_new();

  BN_set_word(b_bn, b);

  int result = BN_cmp(a, b_bn);

  BN_free(b_bn);

  return result;
}

RSA* public_key_from_bytes(const uint8_t *in, size_t in_len) {
	  std::cerr << "!!!!!!!!!!!!!!!! public_key_from_bytes \n";
  Cbs cbs(in, in_len);
  RSA* ret = parse_public_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  return ret;
}

RSA* parse_public_key(Cbs *cbs) {
	  std::cerr << "!!!!!!!!!!!!!!!! parse_public_key \n";
	RSA *rsa = RSA_new();
  if (rsa == NULL) {
	  return NULL;
  }
  BIGNUM *bn_n = NULL;
  BIGNUM *bn_e = NULL;
  Cbs child(NULL, 0);
  if (!cbs_get_asn1(cbs, &child, CBS_ASN1_SEQUENCE, 1)){
    RSA_free(rsa);
    return NULL;
  } else {

    if (!parse_integer(&child, &bn_n) || !parse_integer(&child, &bn_e) || child.len_ != 0) {
      RSA_free(rsa);
      return NULL;
    } else {
  	 RSA_set0_key(rsa, bn_n, bn_e, NULL);
    }
  }

  if (!BN_is_odd(bn_e) ||
      BN_num_bits(bn_e) < 2) {
    RSA_free(rsa);
    return NULL;
  }

  return rsa;
}

int cbs_get_asn1(Cbs *cbs, Cbs *out, unsigned tag_value,
                        int skip_header) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_asn1 \n";
  size_t header_len;
  unsigned tag;
  Cbs throwaway(NULL, 0);

  if (out == NULL) {
    out = &throwaway;
  }

  if (!cbs_get_any_asn1_element(cbs, out, &tag, &header_len, 0) ||
      tag != tag_value) {
    return 0;
  }

  if (skip_header && !cbs_skip(out, header_len)) {
    assert(0);
    return 0;
  }

  return 1;
}

int cbs_skip(Cbs *cbs, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_skip \n";
  const uint8_t *dummy;
  return cbs_get(cbs, &dummy, len);
}

int cbs_get(Cbs *cbs, const uint8_t **p, size_t n) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get \n";
  if (cbs->len_ < n) {
    return 0;
  }

  *p = cbs->data_;
  cbs->data_ += n;
  cbs->len_ -= n;
  return 1;
}

int cbs_get_any_asn1_element(Cbs *cbs, Cbs *out, unsigned *out_tag,
                                    size_t *out_header_len, int ber_ok) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_any_asn1_element \n";
  Cbs header = *cbs;
  Cbs throwaway(NULL, 0);

  if (out == NULL) {
    out = &throwaway;
  }

  unsigned tag;
  if (!parse_asn1_tag(&header, &tag)) {
    return 0;
  }
  if (out_tag != NULL) {
    *out_tag = tag;
  }

  uint8_t length_byte;
  if (!cbs_get_u8(&header, &length_byte)) {
    return 0;
  }

  size_t header_len = cbs->len_ - header.len_;

  size_t len;
  // The format for the length encoding is specified in ITU-T X.690 section
  // 8.1.3.
  if ((length_byte & 0x80) == 0) {
    // Short form length.
    len = ((size_t) length_byte) + header_len;
    if (out_header_len != NULL) {
      *out_header_len = header_len;
    }
  } else {
    // The high bit indicate that this is the long form, while the next 7 bits
    // encode the number of subsequent octets used to encode the length (ITU-T
    // X.690 clause 8.1.3.5.b).
    const size_t num_bytes = length_byte & 0x7f;
    uint32_t len32;

    if (ber_ok && (tag & CBS_ASN1_CONSTRUCTED) != 0 && num_bytes == 0) {
      // indefinite length
      if (out_header_len != NULL) {
        *out_header_len = header_len;
      }
      return cbs_get_bytes(cbs, out, header_len);
    }

    // ITU-T X.690 clause 8.1.3.5.c specifies that the value 0xff shall not be
    // used as the first byte of the length. If this parser encounters that
    // value, num_bytes will be parsed as 127, which will fail the check below.
    if (num_bytes == 0 || num_bytes > 4) {
      return 0;
    }
    if (!cbs_get_u(&header, &len32, num_bytes)) {
      return 0;
    }
    // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
    // with the minimum number of octets.
    if (len32 < 128) {
      // Length should have used short-form encoding.
      return 0;
    }
    if ((len32 >> ((num_bytes-1)*8)) == 0) {
      // Length should have been at least one byte shorter.
      return 0;
    }
    len = len32;
    if (len + header_len + num_bytes < len) {
      // Overflow.
      return 0;
    }
    len += header_len + num_bytes;
    if (out_header_len != NULL) {
      *out_header_len = header_len + num_bytes;
    }
  }

  return cbs_get_bytes(cbs, out, len);
}

int cbs_get_u(Cbs *cbs, uint32_t *out, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_u \n";
  uint32_t result = 0;
  const uint8_t *data;

  if (!cbs_get(cbs, &data, len)) {
    return 0;
  }
  for (size_t i = 0; i < len; i++) {
    result <<= 8;
    result |= data[i];
  }
  *out = result;
  return 1;
}


int cbs_get_bytes(Cbs *cbs, Cbs *out, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_bytes \n";
  const uint8_t *v;
  if (!cbs_get(cbs, &v, len)) {
    return 0;
  }
  cbs_init(out, v, len);
  return 1;
}

void cbs_init(Cbs *cbs, const uint8_t *data, size_t len) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_init \n";
  cbs->data_ = data;
  cbs->len_ = len;
}

int cbs_get_u8(Cbs *cbs, uint8_t *out) {
	  std::cerr << "!!!!!!!!!!!!!!!! cbs_get_u8 \n";
  const uint8_t *v;
  if (!cbs_get(cbs, &v, 1)) {
    return 0;
  }
  *out = *v;
  return 1;
}

int parse_asn1_tag(Cbs *cbs, unsigned *out) {
	  std::cerr << "!!!!!!!!!!!!!!!! parse_asn1_tag \n";
  uint8_t tag_byte;
  if (!cbs_get_u8(cbs, &tag_byte)) {
    return 0;
  }

  // ITU-T X.690 section 8.1.2.3 specifies the format for identifiers with a tag
  // number no greater than 30.
  //
  // If the number portion is 31 (0x1f, the largest value that fits in the
  // allotted bits), then the tag is more than one byte long and the
  // continuation bytes contain the tag number. This parser only supports tag
  // numbers less than 31 (and thus single-byte tags).
  unsigned tag = ((unsigned)tag_byte & 0xe0) << CBS_ASN1_TAG_SHIFT;
  unsigned tag_number = tag_byte & 0x1f;
  if (tag_number == 0x1f) {
    uint64_t v;
    if (!parse_base128_integer(cbs, &v) ||
        // Check the tag number is within our supported bounds.
        v > CBS_ASN1_TAG_NUMBER_MASK ||
        // Small tag numbers should have used low tag number form.
        v < 0x1f) {
      return 0;
    }
    tag_number = (unsigned)v;
  }

  tag |= tag_number;

  *out = tag;
  return 1;
}

int bn_parse_asn1_unsigned(Cbs *cbs, BIGNUM *ret) {
	  std::cerr << "!!!!!!!!!!!!!!!! bn_parse_asn1_unsigned \n";
  Cbs child(NULL, 0);
  if (!cbs_get_asn1(cbs, &child, CBS_ASN1_INTEGER, 1) || child.len_ == 0) {
//      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
    return 0;
  }

  if (child.data_[0] & 0x80) {
//      OPENSSL_PUT_ERROR(BN, BN_R_NEGATIVE_NUMBER);
    return 0;
  }

  // INTEGERs must be minimal.
  if (child.data_[0] == 0x00 &&
      child.len_ > 1 &&
      !(child.data_[1] & 0x80)) {
//      OPENSSL_PUT_ERROR(BN, BN_R_BAD_ENCODING);
    return 0;
  }

  return BN_bin2bn(child.data_, child.len_, ret) != NULL;
}


int parse_base128_integer(Cbs *cbs, uint64_t *out) {
	  std::cerr << "!!!!!!!!!!!!!!!! parse_base128_integer \n";
  uint64_t v = 0;
  uint8_t b;
  do {
    if (!cbs_get_u8(cbs, &b)) {
      return 0;
    }
    if ((v >> (64 - 7)) != 0) {
      // The value is too large.
      return 0;
    }
    if (v == 0 && b == 0x80) {
      // The value must be minimally encoded.
      return 0;
    }
    v = (v << 7) | (b & 0x7f);

    // Values end at an octet with the high bit cleared.
  } while (b & 0x80);

  *out = v;
  return 1;
}


int parse_integer(Cbs *cbs, BIGNUM **out) {
		std::cerr << "!!!!!!!!!!!!!!!! parse_integer \n";

  assert(*out == NULL);
  *out = BN_new();
  if (*out == NULL) {
    return 0;
  }
  return bn_parse_asn1_unsigned(cbs, *out);
}

}  // namespace cbs
}  // namespace openssl

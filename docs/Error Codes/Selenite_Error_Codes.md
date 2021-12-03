# Selenite Error Codes

[TOC]

## Verification (Core Errors)

### 0x0000

`[Verification|0x0000]`

> Invalid Algorithm Type

This error occurs during verification if the algorithm is invalid. Accepted algorithms are:

* ED25519
* BLS
* FALCON512
* FALCON1024
* SPHINCS+

## BLS

### 0x0000

`BLS|0x0000`

> Failed To Decode From Base64 During Aggregation of Signatures

This is due to unwrapping the result from the Base64 decoding process in the `aggregate()` function implemented for `BLSKeypair`

### 0x0001

`BLS|0x0001`

> Failed To Convert To `bls_signature::Signature` when converting from bytes.

This error occurs when constructing the BLS Signature struct in the aggregation function implemented in `BLSKeypair`

### 0x0002

`BLS|0x0002`

> No Signatures Provided To Aggregation Function

This error occurs in the aggregation function if no base64 encoded signatures are provided.

## Falcon

## ED25519

### 0x0000

`ED25519|0x0000`

> Failed To Decode From Hexadecimal For ED25519 Signing Hash

This error occurs when decoding the hexadecimal public key for ED25519.

---

## WARN (Export of Private Key)

### 0x1000

`WARN|0x1000`

The **secret key** was returned for **SPHINCS**+. This is logged as `0x1000`. It can be returned either as Hexadecimal String or Bytes.

### 0x1001

`WARN|0x1001`

The **secret key** was returned for **FALCON512**. This is logged as `0x1001`

### 0x1002

`WARN|0x1002`

The **secret key** was returned for **FALCON1024**. This is logged as `0x1002`

### 0x1003

`WARN|0x1003`

The **secret key** was returned for ED25519. This is logged as `0x1003`

### 0x1004

`WARN|0x1004`

The **secret key** was returned for BLS. This is logged as `0x1004`


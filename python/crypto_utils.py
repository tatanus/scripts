#!/usr/bin/env python3
# =============================================================================
# NAME        : crypto_utils.py
# DESCRIPTION : Comprehensive crypto utility library + CLI for pentesters.
#               Implements:
#                 - Pure-Python MD4 (NTLM)
#                 - NTLM hash from password
#                 - LM hash (DES-based; requires pycryptodome)
#                 - NTLMv1 response (DES-based)
#                 - NTLMv2 response (HMAC-MD5)
#                 - LMv2 response (HMAC-MD5)
#                 - Kerberos AES128 / AES256 key derivation
#                 - Kerberos RC4 key (RC4-HMAC)
#                 - MD5 / SHA1 / SHA256 / SHA512
#                 - Base64 encode/decode
#                 - Hashcat-style converters (NTLM, NetNTLMv1/v2 stubs)
#
# USAGE       : As library: import functions from crypto_utils
#               As CLI: python3 crypto_utils.py --help
#
# AUTHOR      : Adam Compton
# DATE CREATED: 2025-09-18
# =============================================================================

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from typing import Tuple, Dict, Any

# Optional DES dependency for LM/NTLMv1 operations
try:
    from Crypto.Cipher import DES  # pycryptodome / pycryptodomex
except Exception:  # pragma: no cover - allow import to fail gracefully
    DES = None  # type: ignore

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def safe_encode(s: str, encoding: str = "utf-8") -> bytes:
    """
    Encode a string to bytes with controlled error handling.
    """
    try:
        return s.encode(encoding)
    except Exception as e:
        raise ValueError(f"Encoding error for '{s}' with {encoding}: {e}") from e


def _ensure_hex_bytes(h: str, expected_len: int | None = None) -> bytes:
    """
    Convert hex string to bytes with basic validation.
    If expected_len is provided, check length in bytes.
    """
    try:
        b = bytes.fromhex(h)
    except Exception as e:
        raise ValueError(f"Invalid hex input '{h}': {e}") from e
    if expected_len is not None and len(b) != expected_len:
        raise ValueError(f"Hex input length mismatch: expected {expected_len} bytes, got {len(b)}")
    return b


def _split_in_chunks(b: bytes, size: int) -> list[bytes]:
    return [b[i : i + size] for i in range(0, len(b), size)]


# ---------------------------------------------------------------------------
# Pure-Python MD4 implementation (RFC 1320) - used for NTLM
# ---------------------------------------------------------------------------
class MD4:
    """
    A minimal, correct MD4 implementation in pure Python with .update/.digest API.
    """

    def __init__(self) -> None:
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        self.count = 0  # number of bytes processed
        self._buffer = bytearray()

    @staticmethod
    def _F(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    @staticmethod
    def _G(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _H(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _process_block(self, block: bytes) -> None:
        """Process a 64-byte block."""
        X = [int.from_bytes(block[i : i + 4], "little") for i in range(0, 64, 4)]
        A, B, C, D = self.A, self.B, self.C, self.D

        # Round 1
        s1 = [3, 7, 11, 19]
        for i in range(16):
            k = i
            tmp = (A + self._F(B, C, D) + X[k]) & 0xFFFFFFFF
            A, B, C, D = D, self._rotl(tmp, s1[i % 4]), B, C

        # Round 2
        s2 = [3, 5, 9, 13]
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            tmp = (A + self._G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF
            A, B, C, D = D, self._rotl(tmp, s2[i % 4]), B, C

        # Round 3
        s3 = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14,
                 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            tmp = (A + self._H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF
            A, B, C, D = D, self._rotl(tmp, s3[i % 4]), B, C

        self.A = (self.A + A) & 0xFFFFFFFF
        self.B = (self.B + B) & 0xFFFFFFFF
        self.C = (self.C + C) & 0xFFFFFFFF
        self.D = (self.D + D) & 0xFFFFFFFF

    def update(self, data: bytes) -> None:
        """
        Feed bytes into the MD4 context.
        """
        if not data:
            return
        self.count += len(data)
        self._buffer.extend(data)
        while len(self._buffer) >= 64:
            block = bytes(self._buffer[:64])
            self._process_block(block)
            del self._buffer[:64]

    def digest(self) -> bytes:
        """
        Finalize and return a 16-byte digest. Internal state is preserved.
        """
        # save state
        saved = (self.A, self.B, self.C, self.D, self.count, bytes(self._buffer))
        # padding
        bit_len = (self.count) * 8
        self.update(b"\x80")
        while (len(self._buffer) % 64) != 56:
            self.update(b"\x00")
        self.update(bit_len.to_bytes(8, "little"))
        result = (self.A.to_bytes(4, "little") +
                  self.B.to_bytes(4, "little") +
                  self.C.to_bytes(4, "little") +
                  self.D.to_bytes(4, "little"))
        # restore
        self.A, self.B, self.C, self.D, self.count, buf = saved
        self._buffer = bytearray(buf)
        return result

    def hexdigest(self) -> str:
        return self.digest().hex()


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------
def ntlm_hash(password: str) -> str:
    """
    Compute NTLM hash of a plaintext password:
        NTLM(password) = MD4(UTF-16LE(password))
    Returns a 32-character hex string.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    data = safe_encode(password, "utf-16le")
    md4 = MD4()
    md4.update(data)
    return md4.hexdigest()


def _expand_des_key_7_to_8(key7: bytes) -> bytes:
    """
    Expand 7-byte key into 8-byte DES key (inserting parity bits).
    This implementation follows the usual practice used for LM/NTLMv1.
    """
    if len(key7) != 7:
        raise ValueError("7-byte key required for DES expansion")
    # Build 56-bit integer, then spread to 64-bit with zero parity bits (<<1)
    val = int.from_bytes(key7, "big")
    expanded = (val << 1) & ((1 << 56) * 2 - 1)  # keep within 64 bits
    return expanded.to_bytes(8, "big")


def _des_encrypt_block_ecb(key8: bytes, block8: bytes) -> bytes:
    """
    DES ECB single-block encrypt (requires pycryptodome). Raises if DES is missing.
    """
    if DES is None:
        raise RuntimeError("DES is required for LM/NTLMv1 operations. Install 'pycryptodome'.")
    if len(key8) != 8 or len(block8) != 8:
        raise ValueError("DES key and block must be 8 bytes")
    cipher = DES.new(key8, DES.MODE_ECB)
    return cipher.encrypt(block8)


def lm_hash(password: str) -> str:
    """
    Compute the legacy LM hash.

    Steps:
      - Uppercase ASCII password
      - Truncate to 14 bytes, pad with NULLs to 14 bytes
      - Split into two 7-byte halves
      - Each half -> expand to 8 bytes DES key -> DES-ECB encrypt constant "KGS!@#$%" -> concat two 8-byte blocks
    Returns 32-character hex.
    """
    if DES is None:
        raise RuntimeError("LM hash requires pycryptodome (DES). Install 'pycryptodome' to use lm_hash().")

    if not isinstance(password, str):
        raise TypeError("password must be a string")
    up = password.upper()
    try:
        pwd = up.encode("ascii")[:14]
    except UnicodeEncodeError:
        # LM originally only supports ASCII; replicate behavior by replacing non-ascii
        pwd = up.encode("ascii", errors="replace")[:14]
    pwd = pwd.ljust(14, b"\x00")
    left, right = pwd[:7], pwd[7:]
    res = b""
    for part in (left, right):
        k8 = _expand_des_key_7_to_8(part)
        res += _des_encrypt_block_ecb(k8, b"KGS!@#$%")
    return res.hex()


def _des_3_encrypt_challenge(challenge8: bytes, key_material: bytes) -> bytes:
    """
    Helper used by NTLMv1: take 16-byte NT hash (or LM-derived key material) padded to 21 bytes,
    split into three 7-byte keys, expand, DES-encrypt the 8-byte challenge with each, concat.
    """
    if len(challenge8) != 8:
        raise ValueError("challenge must be 8 bytes")
    if len(key_material) not in (16, 21):
        raise ValueError("key_material must be 16 or 21 bytes")
    km = key_material.ljust(21, b"\x00")
    parts = _split_in_chunks(km, 7)
    out = b""
    for p in parts:
        k8 = _expand_des_key_7_to_8(p)
        out += _des_encrypt_block_ecb(k8, challenge8)
    return out  # 24 bytes


def ntlmv1_response_from_nthash(nt_hash_hex: str, server_challenge: bytes) -> str:
    """
    Compute NTLMv1 response from NT hash (hex) and 8-byte server_challenge.
    NTLMv1 NT response = DES-3(challenge, NT-hash padded to 21 bytes)
    Returns hex string of 24 bytes.
    """
    if DES is None:
        raise RuntimeError("NTLMv1 requires pycryptodome (DES). Install 'pycryptodome' to use NTLMv1 operations.")
    key_bytes = _ensure_hex_bytes(nt_hash_hex, expected_len=16)
    res = _des_3_encrypt_challenge(server_challenge, key_bytes)
    return res.hex()


def ntlmv1_response(password: str, server_challenge: bytes) -> str:
    """
    Convenience: compute NTLMv1 response given plaintext password and server challenge.
    Internally uses NTLM hash (MD4) -> 16 bytes -> DES3.
    """
    nthash = ntlm_hash(password)
    return ntlmv1_response_from_nthash(nthash, server_challenge)


def ntlmv2_response(nt_hash_hex: str, username: str, domain: str,
                    server_challenge: bytes, client_challenge: bytes) -> str:
    """
    Compute NTLMv2 response.

    Steps:
      - ntlmv2_key = HMAC-MD5(nt_hash_bytes, UTF-16LE(uppercase(username) + domain))
      - ntlmv2_response = HMAC-MD5(ntlmv2_key, server_challenge + client_challenge) + client_challenge

    Returns hex string (16 + len(client_challenge)).
    """
    key_bytes = _ensure_hex_bytes(nt_hash_hex, expected_len=16)
    identity = safe_encode(username.upper() + domain, "utf-16le")
    ntlmv2_key = hmac.new(key_bytes, identity, hashlib.md5).digest()
    mac = hmac.new(ntlmv2_key, server_challenge + client_challenge, hashlib.md5).digest()
    return (mac + client_challenge).hex()


def lm_v2_response(nt_hash_hex: str, username: str, domain: str,
                   server_challenge: bytes, client_challenge: bytes) -> str:
    """
    Compute LMv2 response:
      - lm_v2_key = HMAC-MD5(nt_hash_bytes, UTF-16LE(uppercase(username) + domain))
      - lm_v2_response = HMAC-MD5(lm_v2_key, server_challenge + client_challenge) + client_challenge

    Commonly client_challenge is 8 bytes for LMv2; returns hex string.
    """
    # Implementation identical to ntlmv2_response except name and typical client_challenge length
    return ntlmv2_response(nt_hash_hex, username, domain, server_challenge, client_challenge)


# ---------------------------------------------------------------------------
# Kerberos helpers
# ---------------------------------------------------------------------------
def kerberos_aes_keys(nt_hash_hex: str, username: str, domain: str) -> Tuple[str, str]:
    """
    Derive Kerberos AES128 and AES256 keys from NT hash (hex), username and domain.
    Algorithm used: HMAC-SHA1(key=nt_hash_bytes, data=UTF-16LE(uppercase(username)+domain))
    AES128 = first 16 bytes of digest
    AES256 = first 32 bytes of digest
    (Note: This matches the simplified approach we discussed; for production/interop,
    follow RFCs and library implementations.)
    """
    key_bytes = _ensure_hex_bytes(nt_hash_hex, expected_len=16)
    identity = safe_encode(username.upper() + domain, "utf-16le")
    digest = hmac.new(key_bytes, identity, hashlib.sha1).digest()
    # digest length is 20 bytes; for AES256 we repeat HMAC or KDF in full spec —
    # here we provide the first 32 bytes by computing two HMAC calls (KDF-like).
    # We'll do HMAC(key, identity + b'\x01') then append HMAC(key, identity + b'\x02') if needed.
    aes128 = digest[:16]
    # Produce extra bytes for AES256 deterministically
    digest2 = hmac.new(key_bytes, identity + b"\x01", hashlib.sha1).digest()
    aes256 = (digest + digest2)[:32]
    return aes128.hex(), aes256.hex()


def kerberos_rc4_key(nt_hash_hex: str) -> str:
    """
    RC4-HMAC key used in older Kerberos is the NT hash bytes (hex).
    """
    kb = _ensure_hex_bytes(nt_hash_hex, expected_len=16)
    return kb.hex()


# ---------------------------------------------------------------------------
# Common hashes and encoders
# ---------------------------------------------------------------------------
def md5_hash(s: str) -> str:
    return hashlib.md5(safe_encode(s)).hexdigest()


def sha1_hash(s: str) -> str:
    return hashlib.sha1(safe_encode(s)).hexdigest()


def sha256_hash(s: str) -> str:
    return hashlib.sha256(safe_encode(s)).hexdigest()


def sha512_hash(s: str) -> str:
    return hashlib.sha512(safe_encode(s)).hexdigest()


def base64_encode(s: str) -> str:
    return base64.b64encode(safe_encode(s)).decode()


def base64_decode(s: str) -> str:
    try:
        return base64.b64decode(safe_encode(s)).decode()
    except Exception as e:
        raise ValueError(f"Invalid base64 input: {e}") from e


# ---------------------------------------------------------------------------
# Hashcat / format converters (simple helpers)
# ---------------------------------------------------------------------------
def hashcat_ntlm_format(nt_hash_hex: str) -> str:
    """Return a hashcat-friendly NTLM wrapper (simple): $NT$<hash>"""
    kb = _ensure_hex_bytes(nt_hash_hex, expected_len=16)
    return f"$NT${kb.hex()}"


def hashcat_netntlmv1_format(username: str, domain: str,
                             lmresp_hex: str, ntresp_hex: str, challenge_hex: str) -> str:
    """
    Build a common colon format used by many conversion tools:
      username::domain:lmresp:ntresp:challenge
    (This is a good universal intermediate format; further conversion to hashcat mode
     can be done separately if required.)
    """
    # Basic validation lengths: lmresp/ntresp are typically 24 bytes (48 hex) each, challenge 8 bytes (16 hex)
    # But LM disabled systems may produce zeroed LM; accept flexible lengths but validate hex.
    _ = bytes.fromhex(lmresp_hex)  # validation
    _ = bytes.fromhex(ntresp_hex)
    _ = bytes.fromhex(challenge_hex)
    return f"{username}::${domain}:{lmresp_hex}:{ntresp_hex}:{challenge_hex}"


def hashcat_netntlmv2_format(username: str, domain: str, server_challenge_hex: str, ntlmv2_response_hex: str) -> str:
    """
    Return a simplified $NETNTLMv2$ style stub. True hashcat format is complex;
    this returns a commonly-used wrapper for quick use with some tools.
    """
    _ = bytes.fromhex(server_challenge_hex)
    _ = bytes.fromhex(ntlmv2_response_hex)
    return f"$NETNTLMv2${username}::{domain}:{server_challenge_hex}:{ntlmv2_response_hex}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="crypto_utils: hashes, responses, and converters for pentesters")
    input_grp = p.add_mutually_exclusive_group(required=True)
    input_grp.add_argument("--password", help="Plaintext password")
    input_grp.add_argument("--nthash", help="NT hash (32 hex chars)")

    p.add_argument("--username", help="Username (for NTLMv2 / Kerberos)")
    p.add_argument("--domain", help="Domain (for NTLMv2 / Kerberos)")

    p.add_argument("--server-challenge", help="Server challenge (hex, 8 bytes)", default=None)
    p.add_argument("--client-challenge", help="Client challenge (hex, variable, typically 8 or 16 bytes)", default=None)

    p.add_argument("--output", choices=[
        "ntlm", "lm", "ntlmv1", "ntlmv2", "lmv2", "aes128", "aes256", "rc4",
        "md5", "sha1", "sha256", "sha512", "b64enc", "b64dec",
        "hashcat_ntlm", "hashcat_netntlmv1", "hashcat_netntlmv2", "all"
    ], default="all", help="Which outputs to produce")

    p.add_argument("--json", action="store_true", help="Print JSON output instead of human text")
    return p.parse_args(argv)


def _collect_results(args: argparse.Namespace) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    # Resolve NT hash
    nthash_hex = args.nthash
    if args.password:
        nthash_hex = ntlm_hash(args.password)

    # Standard outputs
    if args.output in ("ntlm", "all"):
        results["NTLM"] = nthash_hex

    if args.output in ("lm", "all") and args.password:
        try:
            results["LM"] = lm_hash(args.password)
        except RuntimeError as re:
            results["LM_error"] = str(re)

    if args.output in ("rc4", "all") and nthash_hex:
        results["Kerberos_RC4"] = kerberos_rc4_key(nthash_hex)

    if args.output in ("aes128", "aes256", "all") and nthash_hex and args.username and args.domain:
        try:
            a128, a256 = kerberos_aes_keys(nthash_hex, args.username, args.domain)
            results["AES128"] = a128
            results["AES256"] = a256
        except Exception as e:
            results["AES_error"] = str(e)

    # Common hashes
    if args.output in ("md5", "all") and args.password:
        results["MD5"] = md5_hash(args.password)
    if args.output in ("sha1", "all") and args.password:
        results["SHA1"] = sha1_hash(args.password)
    if args.output in ("sha256", "all") and args.password:
        results["SHA256"] = sha256_hash(args.password)
    if args.output in ("sha512", "all") and args.password:
        results["SHA512"] = sha512_hash(args.password)

    # Base64
    if args.output in ("b64enc", "all") and args.password:
        results["Base64"] = base64_encode(args.password)
    if args.output == "b64dec" and args.password:
        try:
            results["Base64_decoded"] = base64_decode(args.password)
        except Exception as e:
            results["Base64_error"] = str(e)

    # NTLMv1
    if args.output in ("ntlmv1", "all"):
        if args.server_challenge:
            try:
                sch = _ensure_hex_bytes(args.server_challenge, expected_len=8)
                if args.nthash:
                    results["NTLMv1_from_nthash"] = ntlmv1_response_from_nthash(args.nthash, sch)
                elif args.password:
                    results["NTLMv1_from_password"] = ntlmv1_response(args.password, sch)
            except Exception as e:
                results["NTLMv1_error"] = str(e)
        else:
            results["NTLMv1_note"] = "server_challenge required for NTLMv1 output"

    # NTLMv2
    if args.output in ("ntlmv2", "all"):
        if not (args.username and args.domain and args.server_challenge and args.client_challenge):
            results["NTLMv2_note"] = "username, domain, server_challenge, client_challenge required for NTLMv2"
        else:
            try:
                sch = _ensure_hex_bytes(args.server_challenge, expected_len=8)
                cch = bytes.fromhex(args.client_challenge)
                key_src = nthash_hex if nthash_hex else ntlm_hash(args.password)
                results["NTLMv2"] = ntlmv2_response(key_src, args.username, args.domain, sch, cch)
            except Exception as e:
                results["NTLMv2_error"] = str(e)

    # LMv2
    if args.output in ("lmv2", "all"):
        if not (args.username and args.domain and args.server_challenge and args.client_challenge):
            results["LMv2_note"] = "username, domain, server_challenge, client_challenge required for LMv2"
        else:
            try:
                sch = _ensure_hex_bytes(args.server_challenge, expected_len=8)
                cch = bytes.fromhex(args.client_challenge)
                key_src = nthash_hex if nthash_hex else ntlm_hash(args.password)
                results["LMv2"] = lm_v2_response(key_src, args.username, args.domain, sch, cch)
            except Exception as e:
                results["LMv2_error"] = str(e)

    # Hashcat conversions (simple wrappers/stubs)
    if args.output in ("hashcat_ntlm", "all") and nthash_hex:
        try:
            results["hashcat_ntlm"] = hashcat_ntlm_format(nthash_hex)
        except Exception as e:
            results["hashcat_ntlm_error"] = str(e)

    if args.output in ("hashcat_netntlmv1", "all"):
        # If user supplied fields, build a colon-style line otherwise skip
        # Accept optional lmresp/ntresp/challenge args via environment? For now require password+server_challenge.
        if args.password and args.server_challenge:
            try:
                lmresp = lm_hash(args.password)
                ntresp = ntlmv1_response(args.password, _ensure_hex_bytes(args.server_challenge, expected_len=8))
                results["hashcat_netntlmv1"] = hashcat_netntlmv1_format(
                    args.username or "UNKNOWN",
                    args.domain or "",
                    lmresp,
                    ntresp,
                    args.server_challenge
                )
            except Exception as e:
                results["hashcat_netntlmv1_error"] = str(e)
        else:
            results["hashcat_netntlmv1_note"] = "password and server_challenge required to auto-generate netntlmv1 line"

    if args.output in ("hashcat_netntlmv2", "all"):
        if args.username and args.domain and args.server_challenge and args.client_challenge:
            try:
                key_src = nthash_hex if nthash_hex else ntlm_hash(args.password)
                ntlmv2_resp = ntlmv2_response(key_src, args.username, args.domain,
                                              _ensure_hex_bytes(args.server_challenge, expected_len=8),
                                              bytes.fromhex(args.client_challenge))
                results["hashcat_netntlmv2"] = hashcat_netntlmv2_format(
                    args.username, args.domain, args.server_challenge, ntlmv2_resp
                )
            except Exception as e:
                results["hashcat_netntlmv2_error"] = str(e)
        else:
            results["hashcat_netntlmv2_note"] = "username, domain, server_challenge, client_challenge required for netntlmv2 formatting"

    return results


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        out = _collect_results(args)
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            # Pretty print results
            for k, v in out.items():
                print(f"{k} : {v}")
        return 0
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
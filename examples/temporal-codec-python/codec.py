"""Payload codec sketch: AES-256-GCM with a key id in payload metadata.

DESIGN, partly tested. The encode/decode round trip, key rotation by key id,
and tamper rejection are unit tested with a fake key (test_codec.py). It has
NOT been run against a Temporal server. Do not put real secret values in
Temporal payloads even with this codec; see docs/temporal.md.
"""

import base64
import os
from typing import Dict, Iterable, List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec

ENCODING = b"binary/encrypted"
KEY_ID_FIELD = "encryption-key-id"
NONCE_LEN = 12


def keys_from_env(environ=os.environ) -> Dict[str, bytes]:
    """Read keys named PHANTOM_TEMPORAL_CODEC_KEY_<ID> (base64, 32 bytes)."""
    prefix = "PHANTOM_TEMPORAL_CODEC_KEY_"
    keys = {}
    for name, value in environ.items():
        if name.startswith(prefix):
            raw = base64.b64decode(value)
            if len(raw) != 32:
                raise ValueError(f"{name} must decode to exactly 32 bytes")
            keys[name[len(prefix):]] = raw
    return keys


class EncryptionCodec(PayloadCodec):
    def __init__(self, keys: Dict[str, bytes], current_key_id: str):
        if current_key_id not in keys:
            raise ValueError("current key id is not in the key set")
        self._keys = keys
        self._current = current_key_id

    async def encode(self, payloads: Iterable[Payload]) -> List[Payload]:
        out = []
        for p in payloads:
            nonce = os.urandom(NONCE_LEN)
            body = AESGCM(self._keys[self._current]).encrypt(
                nonce, p.SerializeToString(), self._current.encode()
            )
            out.append(
                Payload(
                    metadata={
                        "encoding": ENCODING,
                        KEY_ID_FIELD: self._current.encode(),
                    },
                    data=nonce + body,
                )
            )
        return out

    async def decode(self, payloads: Iterable[Payload]) -> List[Payload]:
        out = []
        for p in payloads:
            if p.metadata.get("encoding") != ENCODING:
                out.append(p)
                continue
            key_id = p.metadata[KEY_ID_FIELD].decode()
            key = self._keys.get(key_id)
            if key is None:
                raise ValueError("unknown key id; payload cannot be decoded")
            nonce, body = p.data[:NONCE_LEN], p.data[NONCE_LEN:]
            try:
                plain = AESGCM(key).decrypt(nonce, body, key_id.encode())
            except InvalidTag as exc:
                raise ValueError("payload failed authentication") from exc
            decoded = Payload()
            decoded.ParseFromString(plain)
            out.append(decoded)
        return out

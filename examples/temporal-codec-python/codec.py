"""Payload codec sketch: AES-256-GCM with a key id in payload metadata.

DESIGN, partly tested. The encode/decode round trip, key rotation by key id,
and tamper rejection are unit tested with a fake key (test_codec.py). It has
NOT been run against a Temporal server. Do not put real secret values in
Temporal payloads even with this codec; see docs/temporal.md.
"""

import base64
import binascii
import os
import re
import stat
from typing import Dict, Iterable, List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec

ENCODING = b"binary/encrypted"
KEY_ID_FIELD = "encryption-key-id"
NONCE_LEN = 12


ENV_KEY_PREFIX = "PHANTOM_TEMPORAL_CODEC_KEY_"
# Names under ENV_KEY_PREFIX that are settings, not keys.
RESERVED_KEY_ENV_NAMES = {"PHANTOM_TEMPORAL_CODEC_KEY_ID"}
KEYS_FD_ENV = "PHANTOM_TEMPORAL_CODEC_KEYS_FD"
MAX_KEY_INPUT_BYTES = 64 * 1024
# Key ids are written to payload metadata, so they land in workflow history.
# They must be plain labels, never key material.
KEY_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _decode_key(label: str, value: str) -> bytes:
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{label} is not valid base64") from None
    if len(raw) != 32:
        raise ValueError(f"{label} must decode to exactly 32 bytes")
    return raw


def keys_from_env(environ=os.environ) -> Dict[str, bytes]:
    """Read keys named PHANTOM_TEMPORAL_CODEC_KEY_<ID> (base64, 32 bytes).

    Weaker than keys_from_fd: the values stay in this process's environment,
    where same-user tools can read them and child processes inherit them.
    """
    keys = {}
    for name, value in environ.items():
        if name.startswith(ENV_KEY_PREFIX) and name not in RESERVED_KEY_ENV_NAMES:
            key_id = name[len(ENV_KEY_PREFIX):]
            if not KEY_ID_RE.fullmatch(key_id):
                raise ValueError(f"{name} has an invalid key id")
            keys[key_id] = _decode_key(name, value)
    return keys


def keys_from_fd(fd: int, max_bytes: int = MAX_KEY_INPUT_BYTES) -> Dict[str, bytes]:
    """Read keys once from an inherited pipe or socket, then close it.

    Input is one "<ID>=<base64 32-byte key>" per line. A regular file or a
    terminal is refused so the key does not come from disk or the screen.
    The fd is closed even on error, so later child processes cannot read it.
    """
    try:
        mode = os.fstat(fd).st_mode
        if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
            raise ValueError("key fd must be a pipe or socket, not a file or terminal")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("key input is too large")
            chunks.append(chunk)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        text = b"".join(chunks).decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("key input must be ASCII") from None
    keys = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        key_id, sep, value = line.partition("=")
        key_id = key_id.strip()
        if not sep or not KEY_ID_RE.fullmatch(key_id):
            raise ValueError(f"key input line {number} must be <ID>=<base64>")
        if key_id in keys:
            raise ValueError(f"key input line {number} repeats a key id")
        keys[key_id] = _decode_key(f"key input line {number}", value)
    if not keys:
        raise ValueError("key input holds no keys")
    return keys


def load_keys(environ=os.environ) -> Dict[str, bytes]:
    """Prefer the inherited fd named by PHANTOM_TEMPORAL_CODEC_KEYS_FD.

    The variable holds only an fd number, which is not secret. Mixing the fd
    with PHANTOM_TEMPORAL_CODEC_KEY_<ID> variables is refused.
    """
    fd_text = environ.get(KEYS_FD_ENV)
    if fd_text is None:
        return keys_from_env(environ)
    if not fd_text.isdigit():
        raise ValueError(f"{KEYS_FD_ENV} must be a file descriptor number")
    if keys_from_env_names(environ):
        raise ValueError(f"set {KEYS_FD_ENV} or key variables, not both")
    return keys_from_fd(int(fd_text))


def keys_from_env_names(environ) -> List[str]:
    return [
        n for n in environ
        if n.startswith(ENV_KEY_PREFIX) and n not in RESERVED_KEY_ENV_NAMES
    ]


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

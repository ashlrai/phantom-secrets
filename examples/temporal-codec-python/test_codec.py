import asyncio
import os
import unittest

from temporalio.api.common.v1 import Payload

from codec import EncryptionCodec, keys_from_env

FAKE_A = bytes(range(32))
FAKE_B = bytes(range(32, 64))


def run(coro):
    return asyncio.run(coro)


class CodecTests(unittest.TestCase):
    def sample(self):
        return [Payload(metadata={"encoding": b"json/plain"}, data=b'{"name":"OPENAI_API_KEY"}')]

    def test_round_trip(self):
        codec = EncryptionCodec({"a": FAKE_A}, "a")
        enc = run(codec.encode(self.sample()))
        self.assertEqual(enc[0].metadata["encoding"], b"binary/encrypted")
        self.assertNotIn(b"OPENAI_API_KEY", enc[0].data)
        self.assertEqual(run(codec.decode(enc)), self.sample())

    def test_old_key_still_decodes_after_rotation(self):
        old = EncryptionCodec({"a": FAKE_A}, "a")
        enc = run(old.encode(self.sample()))
        new = EncryptionCodec({"a": FAKE_A, "b": FAKE_B}, "b")
        self.assertEqual(run(new.decode(enc)), self.sample())
        self.assertEqual(run(new.encode(self.sample()))[0].metadata["encryption-key-id"], b"b")

    def test_tamper_and_unknown_key_rejected(self):
        codec = EncryptionCodec({"a": FAKE_A}, "a")
        enc = run(codec.encode(self.sample()))
        enc[0].data = enc[0].data[:-1] + bytes([enc[0].data[-1] ^ 1])
        with self.assertRaises(ValueError):
            run(codec.decode(enc))
        other = EncryptionCodec({"b": FAKE_B}, "b")
        with self.assertRaises(ValueError):
            run(other.decode(run(codec.encode(self.sample()))))

    def test_unencrypted_payloads_pass_through(self):
        codec = EncryptionCodec({"a": FAKE_A}, "a")
        self.assertEqual(run(codec.decode(self.sample())), self.sample())

    def test_key_length_enforced(self):
        import base64
        with self.assertRaises(ValueError):
            keys_from_env({"PHANTOM_TEMPORAL_CODEC_KEY_x": base64.b64encode(b"short").decode()})


if __name__ == "__main__":
    unittest.main()

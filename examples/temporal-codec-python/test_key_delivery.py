"""Key delivery tests: inherited fd reader and env reader. Fake keys only."""

import base64
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

from codec import KEYS_FD_ENV, keys_from_env, keys_from_fd, load_keys

FAKE_A = bytes(range(32))
FAKE_B = bytes(range(32, 64))
B64_A = base64.b64encode(FAKE_A).decode()
B64_B = base64.b64encode(FAKE_B).decode()


def pipe_with(data: bytes) -> int:
    r, w = os.pipe()
    os.write(w, data)
    os.close(w)
    return r


def fd_is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


class FdKeyTests(unittest.TestCase):
    def test_reads_keys_and_closes_fd(self):
        fd = pipe_with(f"a={B64_A}\n\nb={B64_B}\n".encode())
        self.assertEqual(keys_from_fd(fd), {"a": FAKE_A, "b": FAKE_B})
        self.assertFalse(fd_is_open(fd))

    def test_regular_file_refused_and_closed(self):
        with tempfile.TemporaryFile() as f:
            fd = os.dup(f.fileno())
            with self.assertRaisesRegex(ValueError, "pipe or socket"):
                keys_from_fd(fd)
            self.assertFalse(fd_is_open(fd))

    def test_bad_input_refused_without_echoing_values(self):
        cases = {
            "short": f"a={base64.b64encode(bytes(16)).decode()}\n",
            "not base64": "a=not-base64!!\n",
            "no separator": f"{B64_A}\n",
            "bad id": f"a b={B64_A}\n",
            "repeat": f"a={B64_A}\na={B64_B}\n",
            "empty": "\n",
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                fd = pipe_with(data.encode())
                with self.assertRaises(ValueError) as ctx:
                    keys_from_fd(fd)
                self.assertNotIn(B64_A, str(ctx.exception))
                self.assertNotIn(B64_B, str(ctx.exception))
                self.assertFalse(fd_is_open(fd))

    def test_oversize_refused(self):
        fd = pipe_with(b"a" * 5000)
        with self.assertRaisesRegex(ValueError, "too large"):
            keys_from_fd(fd, max_bytes=4096)


class EnvKeyTests(unittest.TestCase):
    def test_key_id_setting_is_not_read_as_a_key(self):
        env = {"PHANTOM_TEMPORAL_CODEC_KEY_a": B64_A, "PHANTOM_TEMPORAL_CODEC_KEY_ID": "a"}
        self.assertEqual(keys_from_env(env), {"a": FAKE_A})

    def test_load_keys_prefers_fd_and_refuses_mixing(self):
        fd = pipe_with(f"a={B64_A}\n".encode())
        env = {KEYS_FD_ENV: str(fd), "PHANTOM_TEMPORAL_CODEC_KEY_ID": "a"}
        self.assertEqual(load_keys(env), {"a": FAKE_A})
        fd = pipe_with(f"a={B64_A}\n".encode())
        mixed = {KEYS_FD_ENV: str(fd), "PHANTOM_TEMPORAL_CODEC_KEY_b": B64_B}
        with self.assertRaisesRegex(ValueError, "not both"):
            load_keys(mixed)
        os.close(fd)
        with self.assertRaisesRegex(ValueError, "descriptor number"):
            load_keys({KEYS_FD_ENV: "three"})


CHILD = textwrap.dedent(
    """
    import os, sys
    sys.path.insert(0, sys.argv[1])
    from codec import load_keys
    keys = load_keys(os.environ)
    with open("/proc/self/cmdline", "rb") as f:
        cmdline = f.read()
    with open("/proc/self/environ", "rb") as f:
        environ = f.read()
    print(sorted(keys), [len(v) for v in keys.values()], flush=True)
    sys.stdout.buffer.write(cmdline + b"\\n" + environ)
    """
)


@unittest.skipUnless(os.path.exists("/proc/self/environ"), "needs Linux /proc")
class InheritedFdProcessTests(unittest.TestCase):
    def test_key_reaches_child_without_argv_or_environ(self):
        r, w = os.pipe()
        env = {k: v for k, v in os.environ.items() if not k.startswith("PHANTOM_TEMPORAL_CODEC_")}
        env[KEYS_FD_ENV] = str(r)
        child = subprocess.Popen(
            [sys.executable, "-c", CHILD, os.path.dirname(os.path.abspath(__file__))],
            env=env, pass_fds=(r,), stdout=subprocess.PIPE,
        )
        os.close(r)
        os.write(w, f"a={B64_A}\n".encode())
        os.close(w)
        out, _ = child.communicate(timeout=60)
        self.assertEqual(child.returncode, 0)
        self.assertTrue(out.startswith(b"['a'] [32]\n"))
        for secret in (B64_A.encode(), FAKE_A):
            self.assertNotIn(secret, out)


if __name__ == "__main__":
    unittest.main()

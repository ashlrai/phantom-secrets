"""Shared client setup for the local end-to-end scripts."""

import dataclasses
import os

import temporalio.converter
from temporalio.client import Client

from codec import EncryptionCodec, load_keys

TASK_QUEUE = "phantom-codec-e2e"


async def connect() -> Client:
    keys = load_keys(os.environ)
    codec = EncryptionCodec(keys, os.environ["PHANTOM_TEMPORAL_CODEC_KEY_ID"])
    converter = dataclasses.replace(temporalio.converter.default(), payload_codec=codec)
    target = os.environ.get("TEMPORAL_ADDRESS", "127.0.0.1:7233")
    return await Client.connect(target, data_converter=converter)

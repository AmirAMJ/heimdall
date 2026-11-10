import struct
from dataclasses import replace

import pytest

from heimdall import crypto, image
from heimdall.errors import ImageFormatError, VerificationError
from heimdall.image import HEADER, MAGIC, Stage


@pytest.fixture
def keypair(tmp_path):
    priv_path, pub_path = crypto.generate_keypair("k", tmp_path)
    return crypto.load_private_key(priv_path), crypto.load_public_key(pub_path)


def test_header_size_is_56():
    assert HEADER.size == 56


def test_roundtrip_unsigned_and_signed(keypair):
    priv, _ = keypair
    built = image.build_image(b"payload", Stage.KERNEL, 7)
    assert image.parse(built.to_bytes()) == built
    signed = image.sign_image(built, priv)
    assert signed.is_signed
    assert image.parse(signed.to_bytes()) == signed


def test_magic_is_first_four_bytes():
    assert image.build_image(b"x", Stage.BL1, 1).to_bytes()[:4] == MAGIC == b"HMDL"


def test_verify_ok(keypair):
    priv, pub = keypair
    image.verify_image(image.sign_image(image.build_image(b"p", Stage.BL2, 1), priv), pub)


def test_payload_tamper_detected(keypair):
    priv, pub = keypair
    data = bytearray(image.sign_image(image.build_image(b"kernel running", Stage.KERNEL, 1), priv).to_bytes())
    data[60] ^= 0xFF
    with pytest.raises(VerificationError, match="payload hash mismatch"):
        image.verify_image(image.parse(bytes(data)), pub)


def test_header_tamper_detected(keypair):
    priv, pub = keypair
    signed = image.sign_image(image.build_image(b"p", Stage.KERNEL, 1), priv)
    with pytest.raises(VerificationError):
        image.verify_image(replace(signed, counter=99), pub)


def test_wrong_key_and_unsigned(keypair, tmp_path):
    priv, pub = keypair
    other_priv = crypto.load_private_key(crypto.generate_keypair("o", tmp_path)[0])
    signed = image.sign_image(image.build_image(b"p", Stage.BL1, 1), other_priv)
    with pytest.raises(VerificationError):
        image.verify_image(signed, pub)
    with pytest.raises(VerificationError, match="not signed"):
        image.verify_image(image.build_image(b"p", Stage.BL1, 1), pub)


def _hdr(**kw):
    f = dict(magic=MAGIC, version=1, stage=1, counter=1, length=0, h=bytes(32), kid=bytes(8))
    f.update(kw)
    return HEADER.pack(f["magic"], f["version"], f["stage"], f["counter"], f["length"], f["h"], f["kid"])


@pytest.mark.parametrize(
    "data,msg",
    [
        (b"", "truncated header"),
        (b"\x00" * 55, "truncated header"),
        (_hdr(magic=b"XXXX"), "bad magic"),
        (_hdr(version=9), "unsupported format version"),
        (_hdr(stage=0), "unknown stage"),
        (_hdr(stage=99), "unknown stage"),
        (_hdr(length=image.MAX_PAYLOAD + 1), "payload too large"),
        (_hdr(length=10), "truncated payload"),
        (_hdr(length=0) + b"\x00" * 5, "trailing bytes"),
    ],
)
def test_malformed_images_rejected(data, msg):
    with pytest.raises(ImageFormatError, match=msg):
        image.parse(data)


def test_build_validates_counter_and_size():
    with pytest.raises(ImageFormatError):
        image.build_image(b"x", Stage.BL1, -1)
    with pytest.raises(ImageFormatError):
        image.build_image(b"x", Stage.BL1, 2**32)
    with pytest.raises(ImageFormatError):
        image.build_image(b"x" * (image.MAX_PAYLOAD + 1), Stage.BL1, 1)


def test_struct_format_is_stable():
    assert HEADER.format == struct.Struct("<4sHHII32s8s").format

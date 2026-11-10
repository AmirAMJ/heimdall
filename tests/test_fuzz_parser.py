"""Property tests: the parser and verifier must never crash on hostile input."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from heimdall import crypto, image
from heimdall.errors import ImageFormatError, VerificationError
from heimdall.image import Stage


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=400))
def test_parse_never_raises_anything_but_imageformaterror(data):
    try:
        parsed = image.parse(data)
    except ImageFormatError:
        return
    assert isinstance(parsed, image.Image)


@pytest.fixture(scope="module")
def signed(tmp_path_factory):
    d = tmp_path_factory.mktemp("fuzz")
    priv_path, pub_path = crypto.generate_keypair("k", d)
    priv, pub = crypto.load_private_key(priv_path), crypto.load_public_key(pub_path)
    built = image.sign_image(image.build_image(b"kernel running", Stage.KERNEL, 1), priv)
    return built.to_bytes(), pub


@settings(max_examples=300, deadline=None)
@given(st.data())
def test_any_single_byte_mutation_is_rejected(signed, data):
    good, pub = signed
    index = data.draw(st.integers(0, len(good) - 1))
    delta = data.draw(st.integers(1, 255))
    mutated = bytearray(good)
    mutated[index] ^= delta
    with pytest.raises((ImageFormatError, VerificationError)):
        image.verify_image(image.parse(bytes(mutated)), pub)


@settings(max_examples=200, deadline=None)
@given(st.integers(0, 2000))
def test_any_truncation_is_rejected(signed, cut):
    good, pub = signed
    if cut >= len(good):
        return
    with pytest.raises((ImageFormatError, VerificationError)):
        image.verify_image(image.parse(good[:cut]), pub)

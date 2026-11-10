"""Shared fixture: a fully provisioned boot environment in a temp directory."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from heimdall import chain, crypto, image, rom
from heimdall.image import Stage
from heimdall.keystore import Keystore

STAGES = (("bl1", Stage.BL1), ("bl2", Stage.BL2), ("kernel", Stage.KERNEL))


@dataclass
class Env:
    root: Path
    key_paths: dict = field(default_factory=dict)
    images: dict = field(default_factory=dict)

    @property
    def fuses(self) -> Path:
        return self.root / "state" / "fuses.json"

    @property
    def keystore(self) -> Path:
        return self.root / "state" / "keystore.json"

    @property
    def events(self) -> Path:
        return self.root / "state" / "events.json"

    def priv(self, name):
        return crypto.load_private_key(self.key_paths[name][0])

    def pub(self, name):
        return crypto.load_public_key(self.key_paths[name][1])

    def make_image(self, name, counter=1, payload=None, signer="db", stage=None) -> Path:
        stage_id = stage if stage is not None else dict(STAGES)[name]
        payload = payload if payload is not None else f"{name} running".encode()
        built = image.build_image(payload, stage_id, counter)
        if signer:
            built = image.sign_image(built, self.priv(signer))
        path = self.root / f"{name}-{counter}-{signer}.img"
        path.write_bytes(built.to_bytes())
        return path

    def boot(self, **overrides):
        args = dict(
            bl1=self.images["bl1"],
            bl2=self.images["bl2"],
            kernel=self.images["kernel"],
            pk_pub=self.pub("pk"),
            fuses_path=self.fuses,
            keystore_path=self.keystore,
            events_path=self.events,
            executor=lambda stage, payload: None,
        )
        args.update(overrides)
        return chain.boot(**args)


@pytest.fixture
def env(tmp_path) -> Env:
    e = Env(root=tmp_path)
    for name in ("pk", "kek", "db", "evil"):
        e.key_paths[name] = crypto.generate_keypair(name, tmp_path / "keys")
    ks = Keystore()
    ks.enroll("kek", e.pub("kek"))
    ks.enroll("db", e.pub("db"))
    ks.enroll_pk(e.pub("pk"), e.priv("pk"))
    ks.save(e.keystore)
    rom.provision(e.fuses, e.pub("pk"))
    for name, _ in STAGES:
        e.images[name] = e.make_image(name)
    return e

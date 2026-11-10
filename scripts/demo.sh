#!/usr/bin/env bash
# Heimdall end-to-end demo: provision, boot, tamper, attacker key, rollback, revoke, measured boot.
# Run from anywhere after `pip install -e .`; everything happens in a throw-away temp dir.
set -euo pipefail
command -v heimdall >/dev/null || { echo "install first: pip install -e ."; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
H=(heimdall --state-dir "$WORK/state")
BOOT=("${H[@]}" boot --bl1 bl1.img --bl2 bl2.img --pk-pub keys/pk.pub.pem)

step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
expect_fail() {
  if "$@"; then echo "UNEXPECTED SUCCESS"; exit 1; else echo "  -> refused as expected (exit $?)"; fi
}
make_image() {  # make_image <stage> <counter> <text> <signing-key> <out>
  echo "$3" > "$1.payload"
  heimdall build-image --payload "$1.payload" --stage "$1" --counter "$2" --out "$5" >/dev/null
  heimdall sign --key "keys/$4.key.pem" "$5" >/dev/null
}

step "1. Generate keys (PK, KEK, db, and an attacker key)"
for k in pk kek db evil; do heimdall keygen --name "$k" >/dev/null; done
ls keys

step "2. Build and sign the three boot stages with the db key"
make_image bl1 1 "bl1 running" db bl1.img
make_image bl2 1 "bl2 running" db bl2.img
make_image kernel 1 "kernel v1 running" db kernel.img
heimdall verify --pub keys/db.pub.pem kernel.img

step "3. Provision fuses; enroll KEK/db in setup mode; enroll PK to switch to user mode"
"${H[@]}" provision --pk-pub keys/pk.pub.pem
"${H[@]}" status
"${H[@]}" enroll kek --pub keys/kek.pub.pem
"${H[@]}" enroll db  --pub keys/db.pub.pem
"${H[@]}" enroll pk  --pub keys/pk.pub.pem --signed-by keys/pk.key.pem
"${H[@]}" keystore show

step "4. Normal measured boot, then seal a secret to this boot state"
"${BOOT[@]}" --kernel kernel.img --measure
"${H[@]}" replay-log
"${H[@]}" seal --secret "launch-codes"
"${H[@]}" unseal

step "5. ATTACK: flip one byte in the kernel"
cp kernel.img kernel.bad
printf '\x00' | dd of=kernel.bad bs=1 seek=60 conv=notrunc 2>/dev/null
expect_fail "${BOOT[@]}" --kernel kernel.bad

step "6. ATTACK: kernel signed by an attacker key"
make_image kernel 1 "EVIL kernel" evil kernel.evil
expect_fail "${BOOT[@]}" --kernel kernel.evil

step "7. A different but validly signed kernel boots, and the sealed secret stays locked"
make_image kernel 2 "kernel v2 running" db kernel2.img
"${BOOT[@]}" --kernel kernel2.img --measure
expect_fail "${H[@]}" unseal

step "8. ATTACK: roll back to the old (vulnerable) kernel v1"
expect_fail "${BOOT[@]}" --kernel kernel.img

step "9. Revoke kernel v2 in dbx: valid signature, still refused"
"${H[@]}" revoke --image-hash "$(heimdall hash kernel2.img)" --signed-by keys/kek.key.pem
expect_fail "${BOOT[@]}" --kernel kernel2.img

printf '\n\033[1;32mAll attacks refused. Demo complete.\033[0m\n'

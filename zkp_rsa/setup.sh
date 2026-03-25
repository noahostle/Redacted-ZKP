#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BUILD_DIR="build"
CIRCUIT="zk_attest.circom"
PTAU_POWER="21"
PTAU0="$BUILD_DIR/pot${PTAU_POWER}_0000.ptau"
PTAU1="$BUILD_DIR/pot${PTAU_POWER}_0001.ptau"
PTAU_FINAL="$BUILD_DIR/pot${PTAU_POWER}_final.ptau"
ZKEY0="$BUILD_DIR/circuit_0000.zkey"
ZKEY_FINAL="$BUILD_DIR/circuit_final.zkey"
VKEY="$BUILD_DIR/verification_key.json"
R1CS="$BUILD_DIR/zk_attest.r1cs"
SNARKJS="npm exec --yes --package=node@20 -- node /usr/local/lib/node_modules/snarkjs/build/cli.cjs"

command -v circom >/dev/null 2>&1 || { echo "[-] circom not found on PATH"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "[-] node not found on PATH"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "[-] npm not found on PATH"; exit 1; }

mkdir -p "$BUILD_DIR"

if [ ! -d node_modules ]; then
  echo "[*] Installing npm dependencies..."
  npm install
fi

echo "[*] Compiling RSA circuit..."
time circom "$CIRCUIT" --r1cs --wasm --sym -o "$BUILD_DIR"

echo "[*] Inspecting R1CS..."
time $SNARKJS r1cs info "$R1CS"

if [ ! -f "$PTAU_FINAL" ]; then
  echo "[*] Creating Powers of Tau (bn128, 2^${PTAU_POWER})..."
  time $SNARKJS powersoftau new bn128 "$PTAU_POWER" "$PTAU0" -v
  time $SNARKJS powersoftau contribute "$PTAU0" "$PTAU1" --name=demo -e=redacted-zkp-demo -v
  time $SNARKJS powersoftau prepare phase2 "$PTAU1" "$PTAU_FINAL" -v
fi

echo "[*] Running Groth16 setup..."
time $SNARKJS groth16 setup "$R1CS" "$PTAU_FINAL" "$ZKEY0"

echo "[*] Contributing final zkey..."
time $SNARKJS zkey contribute "$ZKEY0" "$ZKEY_FINAL" --name=demo -e=redacted-zkp-demo-zkey -v

echo "[*] Exporting verification key..."
time $SNARKJS zkey export verificationkey "$ZKEY_FINAL" "$VKEY"

echo "[+] RSA compile/setup complete"
echo "    R1CS: $R1CS"
echo "    ZKey: $ZKEY_FINAL"
echo "    VKey: $VKEY"

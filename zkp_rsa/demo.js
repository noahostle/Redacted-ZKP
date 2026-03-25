#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const { startDemo, truncateUtf8Text } = require("./demo_web_common");

const ROOT = process.cwd();
const BUILD_DIR = path.join(ROOT, "build");
const N = 256;

startDemo({
  algorithmId: "rsa",
  demoTitle: "RSA Redacted Signature Demo",
  stateDirName: "demo_state_rsa",
  buildDirName: "build",
  circuitFile: "zk_attest.circom",
  circomArgs: ["--r1cs", "--wasm", "--sym", "-o", "build"],
  circuitId: "zk_attest_rsa_sha256_compressed_redaction_256",
  artifacts: {
    wasm: path.join(BUILD_DIR, "zk_attest_js", "zk_attest.wasm"),
    witnessGenerator: path.join(BUILD_DIR, "zk_attest_js", "generate_witness.js"),
    zkey: path.join(BUILD_DIR, "circuit_final.zkey"),
    vkey: path.join(BUILD_DIR, "verification_key.json"),
    r1cs: path.join(BUILD_DIR, "zk_attest.r1cs"),
  },

  createSigner: async function (label) {
    const keyPair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001,
    });

    const publicKey = keyPair.publicKey;
    const privateKey = keyPair.privateKey;
    const publicPem = publicKey.export({ type: "pkcs1", format: "pem" });
    const privatePem = privateKey.export({ type: "pkcs1", format: "pem" });
    const modulusBuffer = readRsaModulusFromPkcs1Der(publicKey.export({ type: "pkcs1", format: "der" }));
    const modulusBigInt = bytesToBigIntBE(modulusBuffer);
    const modulusHex = "0x" + modulusBigInt.toString(16);

    return {
      label: label,
      scheme: "RSA_PKCS1v15_SHA256",
      publicExponent: 65537,
      modulus_bits: 2048,
      modulus: bigIntToLimbs64LE(modulusBigInt, 32),
      exp: bigIntToLimbs64LE(65537n, 32),
      modulus_hex: modulusHex,
      pub_pem: publicPem,
      priv_pem: privatePem,
      public_summary: "RSA-2048 | e = 65537 | modulus " + modulusHex.slice(0, 22) + "...",
    };
  },

  signMessage: async function (text, signer) {
    const normalized = truncateUtf8Text(text, N);
    const messageBuffer = Buffer.from(normalized.bytes);
    const signatureBuffer = signRsaPkcs1Sha256(messageBuffer, signer.priv_pem);
    const signatureBigInt = bytesToBigIntBE(signatureBuffer);

    return {
      scheme: "RSA_PKCS1v15_SHA256",
      N: N,
      signer_label: signer.label,
      msg_text_utf8: normalized.text,
      msg_len: normalized.msgLen,
      msg: normalized.bytes.map(String),
      modulus: signer.modulus,
      exp: signer.exp,
      sign: bigIntToLimbs64LE(signatureBigInt, 32),
      modulus_hex: signer.modulus_hex,
      public_summary: signer.public_summary,
    };
  },

  makeProofInput: async function (signed, redaction) {
    return {
      masked: redaction.masked,
      modulus: signed.modulus,
      exp: signed.exp,
      msg: signed.msg,
      msg_len: String(signed.msg_len),
      reveal: redaction.reveal,
      sign: signed.sign,
    };
  },

  proofPublicMeta: function (signed) {
    return {
      modulus: signed.modulus,
      exp: signed.exp,
      modulus_hex: signed.modulus_hex,
    };
  },
});

function readRsaModulusFromPkcs1Der(buffer) {
  let offset = expectDerTag(buffer, 0, 0x30);
  const sequenceLength = readDerLength(buffer, offset);
  offset = sequenceLength.nextOffset;

  const modulus = readDerInteger(buffer, offset);
  return modulus.value;
}

function expectDerTag(buffer, offset, expectedTag) {
  if (buffer[offset] !== expectedTag) {
    throw new Error("Unexpected DER tag while decoding RSA public key.");
  }
  return offset + 1;
}

function readDerLength(buffer, offset) {
  const first = buffer[offset];
  if (first < 0x80) {
    return { length: first, nextOffset: offset + 1 };
  }

  const byteCount = first & 0x7f;
  let length = 0;
  for (let i = 0; i < byteCount; i++) {
    length = (length << 8) | buffer[offset + 1 + i];
  }

  return { length: length, nextOffset: offset + 1 + byteCount };
}

function readDerInteger(buffer, offset) {
  offset = expectDerTag(buffer, offset, 0x02);
  const lengthInfo = readDerLength(buffer, offset);
  const start = lengthInfo.nextOffset;
  const end = start + lengthInfo.length;
  let value = buffer.slice(start, end);

  if (value.length > 1 && value[0] === 0) {
    value = value.slice(1);
  }

  return {
    value: value,
    nextOffset: end,
  };
}

function signRsaPkcs1Sha256(messageBuffer, privatePem) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "redacted-rsa-"));
  const keyPath = path.join(tempDir, "key.pem");
  const msgPath = path.join(tempDir, "message.bin");

  fs.writeFileSync(keyPath, privatePem);
  fs.writeFileSync(msgPath, messageBuffer);

  try {
    const result = spawnSync("openssl", ["dgst", "-sha256", "-sign", keyPath, msgPath], {
      encoding: null,
      maxBuffer: 1024 * 1024 * 16,
    });

    if (result.status !== 0) {
      const stderr = result.stderr ? result.stderr.toString("utf8") : "";
      throw new Error(stderr.trim() || "openssl signing failed");
    }

    return Buffer.from(result.stdout);
  } finally {
    if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
    if (fs.existsSync(msgPath)) fs.unlinkSync(msgPath);
    if (fs.existsSync(tempDir)) fs.rmdirSync(tempDir);
  }
}

function bytesToBigIntBE(buffer) {
  return BigInt("0x" + Buffer.from(buffer).toString("hex"));
}

function bigIntToLimbs64LE(value, limbs) {
  const mask = (1n << 64n) - 1n;
  const output = new Array(limbs);
  let current = value;

  for (let i = 0; i < limbs; i++) {
    output[i] = (current & mask).toString();
    current >>= 64n;
  }

  return output;
}

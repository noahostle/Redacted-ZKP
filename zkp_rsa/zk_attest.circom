pragma circom 2.0.0;

include "node_modules/circomlib/circuits/sha256/sha256.circom";
include "rsa_helpers/rsa_verify.circom";
include "redaction_helpers.circom";

template ZkAttest_Redacted_RSA_PKCS1v15_SHA256() {
    var REDACTION_SENTINEL = 1;

    // Public
    signal input masked[256];
    signal input modulus[32];
    signal input exp[32];

    // Private
    signal input msg[256];
    signal input msg_len;
    signal input reveal[256];
    signal input sign[32];

    // 1) Redaction consistency:
    // The public `masked` text is now a compressed token stream where each
    // hidden run is represented by a single sentinel byte.
    component redaction = CompressedRedactionMask(256, REDACTION_SENTINEL);
    redaction.msg_len <== msg_len;
    for (var i = 0; i < 256; i++) {
        redaction.masked[i] <== masked[i];
        redaction.msg[i] <== msg[i];
        redaction.reveal[i] <== reveal[i];
    }

    // 2) Byte -> bits using circomlib Num2Bits(8)
    component mBits[256];
    for (var i = 0; i < 256; i++) {
        mBits[i] = Num2Bits(8);
        mBits[i].in <== msg[i];
    }

    // 3) SHA-256 over 256 bytes => 2048 bits
    component sha = Sha256(256 * 8);

    // Sha256 expects MSB-first bits per byte.
    // Num2Bits outputs LSB-first: out[0]=LSB ... out[7]=MSB.
    for (var i = 0; i < 256; i++) {
        for (var b = 0; b < 8; b++) {
            sha.in[i*8 + b] <== mBits[i].out[7 - b];
        }
    }

    signal digestBits[256];
    for (var i = 0; i < 256; i++) {
        digestBits[i] <== sha.out[i];
    }

    // 4) digestBits -> digestByte[32] (MSB-first bits per byte)
    signal byteAcc[32][9];
    signal digestByte[32];

    for (var j = 0; j < 32; j++) {
        byteAcc[j][0] <== 0;
        for (var b = 0; b < 8; b++) {
            byteAcc[j][b+1] <== byteAcc[j][b] * 2 + digestBits[j*8 + b];
        }
        digestByte[j] <== byteAcc[j][8];
    }

    // 5) Pack digest bytes into 4×64-bit words:
    // hashed[0]=H[24..31], hashed[1]=H[16..23], hashed[2]=H[8..15], hashed[3]=H[0..7]
    signal limbAcc[4][9];
    signal hashed[4];

    for (var k = 0; k < 4; k++) {
        limbAcc[k][0] <== 0;
        for (var t = 0; t < 8; t++) {
            var idx = (3 - k) * 8 + t;
            limbAcc[k][t+1] <== limbAcc[k][t] * 256 + digestByte[idx];
        }
        hashed[k] <== limbAcc[k][8];
    }

    // 6) Constrain exponent = 65537 (assumes exp[0] is least-significant limb)
    exp[0] === 65537;
    for (var i = 1; i < 32; i++) {
        exp[i] === 0;
    }

    // 7) RSA verify (constraints enforced inside helper)
    component rv = RsaVerifyPkcs1v15(64, 32, 17, 4);

    for (var i = 0; i < 32; i++) {
        rv.exp[i] <== exp[i];
        rv.sign[i] <== sign[i];
        rv.modulus[i] <== modulus[i];
    }
    for (var i = 0; i < 4; i++) {
        rv.hashed[i] <== hashed[i];
    }
}

component main { public [masked, modulus, exp] } = ZkAttest_Redacted_RSA_PKCS1v15_SHA256();

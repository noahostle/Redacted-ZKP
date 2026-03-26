const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const MAX_MESSAGE_BYTES = 256;
const REDACTION_SENTINEL = 1;
const DEFAULT_PORT = 4410;

function startDemo(config) {
  const ctx = createContext(config);
  ensureDirs(ctx);

  const server = http.createServer(function (req, res) {
    const started = process.hrtime.bigint();
    logRequestStart(req);
    res.on("finish", function () {
      const ms = Number(process.hrtime.bigint() - started) / 1000000;
      logRequestFinish(req, res, ms);
    });

    routeRequest(ctx, req, res).catch(function (err) {
      console.error("[http] !! " + req.method + " " + req.url);
      console.error(err && err.stack ? err.stack : String(err));
      if (!res.headersSent) {
        sendJson(res, 500, { error: err.message });
      }
    });
  });

  server.listen(ctx.port, function () {
    console.log("");
    console.log("[+] " + ctx.demoTitle + " demo ready");
    console.log("[+] Open http://127.0.0.1:" + ctx.port);
    console.log("");
  });
}

function createContext(config) {
  const rootDir = config.rootDir || process.cwd();
  const stateDir = path.join(rootDir, config.stateDirName);
  const keyDir = path.join(stateDir, "keys");
  const messageDir = path.join(stateDir, "messages");
  const proofDir = path.join(stateDir, "proofs");
  const publicDir = path.join(rootDir, "public");
  const downloadDir = path.join(stateDir, "downloads");
  const buildDir = path.join(rootDir, config.buildDirName);
  const assetsDir = path.join(rootDir, "demo_web_assets");

  return {
    config: config,
    rootDir: rootDir,
    stateDir: stateDir,
    keyDir: keyDir,
    messageDir: messageDir,
    proofDir: proofDir,
    publicDir: publicDir,
    downloadDir: downloadDir,
    buildDir: buildDir,
    assetsDir: assetsDir,
    workDir: path.join(buildDir, "demo_work"),
    buildInfoPath: path.join(stateDir, "last_build.json"),
    port: config.port || DEFAULT_PORT,
    demoTitle: config.demoTitle,
  };
}

function ensureDirs(ctx) {
  fs.mkdirSync(ctx.stateDir, { recursive: true });
  fs.mkdirSync(ctx.keyDir, { recursive: true });
  fs.mkdirSync(ctx.messageDir, { recursive: true });
  fs.mkdirSync(ctx.proofDir, { recursive: true });
  fs.mkdirSync(ctx.publicDir, { recursive: true });
  fs.mkdirSync(ctx.downloadDir, { recursive: true });
  fs.mkdirSync(ctx.buildDir, { recursive: true });
}

async function routeRequest(ctx, req, res) {
  const url = new URL(req.url, "http://127.0.0.1");

  if (req.method === "GET" && url.pathname === "/") {
    return serveFile(res, path.join(ctx.assetsDir, "index.html"), "text/html; charset=utf-8");
  }

  if (req.method === "GET" && url.pathname === "/app.js") {
    return serveFile(res, path.join(ctx.assetsDir, "app.js"), "application/javascript; charset=utf-8");
  }

  if (req.method === "GET" && url.pathname === "/styles.css") {
    return serveFile(res, path.join(ctx.assetsDir, "styles.css"), "text/css; charset=utf-8");
  }

  if (req.method === "GET" && url.pathname === "/api/download") {
    return serveDownloadArchive(ctx, res, url.searchParams.get("name") || "");
  }

  if (req.method === "GET" && url.pathname === "/api/config") {
    return sendJson(res, 200, {
      algorithmId: ctx.config.algorithmId,
      demoTitle: ctx.demoTitle,
      redactionSentinel: REDACTION_SENTINEL,
      maxMessageBytes: MAX_MESSAGE_BYTES,
    });
  }

  if (req.method === "GET" && url.pathname === "/api/state") {
    return sendJson(res, 200, await getState(ctx));
  }

  if (req.method === "POST" && url.pathname === "/api/build") {
    return sendJson(res, 200, await rebuildArtifacts(ctx));
  }

  if (req.method === "POST" && url.pathname === "/api/signers") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await createSigner(ctx, body));
  }

  if (req.method === "POST" && url.pathname === "/api/messages") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await createSignedMessage(ctx, body));
  }

  if (req.method === "POST" && url.pathname === "/api/proofs") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await createProof(ctx, body));
  }

  if (req.method === "POST" && url.pathname === "/api/verify") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await verifyStoredProof(ctx, body));
  }

  if (req.method === "POST" && url.pathname === "/api/export") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await exportProofBundle(ctx, body));
  }

  if (req.method === "POST" && url.pathname === "/api/reset") {
    return sendJson(res, 200, await resetState(ctx));
  }

  sendJson(res, 404, { error: "Not found" });
}

function logRequestStart(req) {
  console.log("[http] --> " + req.method + " " + req.url);
}

function logRequestFinish(req, res, ms) {
  console.log("[http] <-- " + req.method + " " + req.url + " " + res.statusCode + " " + Math.round(ms) + "ms");
}

function logRequestBody(req, body) {
  console.log("[http] body " + req.method + " " + req.url);
  console.log(formatLogValue(body));
}

function formatLogValue(value) {
  if (typeof value === "string") {
    return value;
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch (err) {
    return String(value);
  }
}

async function getState(ctx) {
  const signers = listJsonFiles(ctx.keyDir).map(function (file) {
    const record = readJson(path.join(ctx.keyDir, file));
    return summarizeSigner(file, record);
  });

  const messages = listJsonFiles(ctx.messageDir).map(function (file) {
    const record = readJson(path.join(ctx.messageDir, file));
    return summarizeMessage(file, record);
  }).sort(sortByNewest);

  const proofs = listJsonFiles(ctx.proofDir).map(function (file) {
    const record = readJson(path.join(ctx.proofDir, file));
    return summarizeProof(file, record);
  }).sort(sortByNewest);

  const bundles = listDirectories(ctx.publicDir).map(function (name) {
    const metaPath = path.join(ctx.publicDir, name, "meta.json");
    const meta = fs.existsSync(metaPath) ? readJson(metaPath) : {};
    return {
      name: name,
      created_at: meta.created_at || 0,
      signer_label: meta.signer_label || "",
      masked_control_text: meta.masked_control_text || "",
    };
  }).sort(sortByNewest);

  return {
    artifacts_ready: artifactsExist(ctx),
    build_info: fs.existsSync(ctx.buildInfoPath) ? readJson(ctx.buildInfoPath) : null,
    signers: signers,
    messages: messages,
    proofs: proofs,
    bundles: bundles,
  };
}

function summarizeSigner(file, record) {
  return {
    file: file,
    label: record.label,
    public_summary: record.public_summary || "",
    signature_scheme: formatSignatureScheme(record.scheme),
    keypair_type: buildKeypairType(record),
    public_exponent: readPublicExponent(record),
    modulus_hex: record.modulus_hex || "",
  };
}

function summarizeMessage(file, record) {
  return {
    file: file,
    created_at: record.created_at || 0,
    signer_label: record.signer_label,
    scheme: record.scheme,
    msg_text_utf8: record.msg_text_utf8,
    msg_len: record.msg_len,
    signature_preview: buildSignaturePreview(record),
    signature_full: buildFullSignature(record),
    public_summary: record.public_summary || "",
  };
}

function summarizeProof(file, record) {
  return {
    file: file,
    created_at: record.created_at || 0,
    signer_label: record.signer_label,
    scheme: record.scheme,
    circuit: record.circuit,
    masked_control_text: record.masked_control_text,
    masked_display_text: record.masked_display_text,
    public_summary: record.public_summary || "",
    timings: record.timings || {},
  };
}

function sortByNewest(a, b) {
  return (b.created_at || 0) - (a.created_at || 0);
}

function formatSignatureScheme(scheme) {
  if (scheme === "RSA_PKCS1v15_SHA256") {
    return "RSA PKCS#1 v1.5";
  }

  if (!scheme) {
    return "";
  }

  return String(scheme).replace(/_/g, " ");
}

function buildKeypairType(record) {
  if (record && record.modulus_bits) {
    return "RSA-" + String(record.modulus_bits);
  }
  return "";
}

function readPublicExponent(record) {
  if (record && record.publicExponent !== undefined && record.publicExponent !== null) {
    return String(record.publicExponent);
  }

  if (record && Array.isArray(record.exp) && record.exp.length > 0) {
    let value = 0n;
    for (let i = record.exp.length - 1; i >= 0; i--) {
      value = (value << 64n) + BigInt(record.exp[i] || 0);
    }
    return value.toString();
  }

  return "";
}

function buildSignaturePreview(record) {
  if (record && record.sig) {
    return [
      "R8x " + previewScalar(record.sig.R8x),
      "R8y " + previewScalar(record.sig.R8y),
      "S " + previewScalar(record.sig.S),
    ].join(" | ");
  }

  if (record && Array.isArray(record.sign) && record.sign.length > 0) {
    return previewHex(limbs64LEToHex(record.sign));
  }

  return "";
}

function buildFullSignature(record) {
  if (record && record.sig) {
    return [
      "R8x " + String(record.sig.R8x || ""),
      "R8y " + String(record.sig.R8y || ""),
      "S " + String(record.sig.S || ""),
    ].join("\n");
  }

  if (record && Array.isArray(record.sign) && record.sign.length > 0) {
    return limbs64LEToHex(record.sign);
  }

  return "";
}

function previewScalar(value) {
  const text = String(value || "");
  return text.length > 18 ? text.slice(0, 18) + "..." : text;
}

function previewHex(value) {
  return value.length > 34 ? value.slice(0, 34) + "..." : value;
}

function limbs64LEToHex(limbs) {
  let value = 0n;
  for (let i = limbs.length - 1; i >= 0; i--) {
    value = (value << 64n) + BigInt(limbs[i] || 0);
  }
  return "0x" + value.toString(16);
}

async function createSigner(ctx, body) {
  const label = sanitizeLabel(body && body.label);
  const chosenLabel = label || nextAutoLabel(ctx);
  const signerPath = path.join(ctx.keyDir, chosenLabel + ".json");

  if (fs.existsSync(signerPath)) {
    throw new Error("Signer already exists: " + chosenLabel);
  }

  const record = await ctx.config.createSigner(chosenLabel, ctx);
  record.label = chosenLabel;
  record.created_at = Date.now();
  writeJson(signerPath, record);

  return {
    ok: true,
    signer: summarizeSigner(chosenLabel + ".json", record),
  };
}

async function createSignedMessage(ctx, body) {
  const text = body && typeof body.text === "string" ? body.text : "";
  const signerLabel = body && body.signer_label ? sanitizeLabel(body.signer_label) : "";

  if (!signerLabel) {
    throw new Error("Select a signer first.");
  }

  const signerPath = path.join(ctx.keyDir, signerLabel + ".json");
  if (!fs.existsSync(signerPath)) {
    throw new Error("Signer not found: " + signerLabel);
  }

  const signer = readJson(signerPath);
  const signedRecord = await ctx.config.signMessage(text, signer, ctx);
  signedRecord.created_at = Date.now();

  const file = "message_" + signerLabel + "_" + signedRecord.created_at + ".json";
  writeJson(path.join(ctx.messageDir, file), signedRecord);

  return {
    ok: true,
    message: summarizeMessage(file, signedRecord),
  };
}

async function createProof(ctx, body) {
  await ensureArtifacts(ctx);

  const messageFile = body && body.message_file ? body.message_file : "";
  if (!messageFile) {
    throw new Error("Choose a signed message.");
  }

  const messagePath = path.join(ctx.messageDir, messageFile);
  if (!fs.existsSync(messagePath)) {
    throw new Error("Signed message not found.");
  }

  const signed = readJson(messagePath);
  const redaction = buildCompressedRedaction(
    signed.msg_text_utf8,
    signed.msg,
    signed.msg_len,
    body && body.ranges ? body.ranges : []
  );

  resetWorkDir(ctx);

  const input = await ctx.config.makeProofInput(signed, redaction, ctx);
  const inputPath = path.join(ctx.workDir, "input.json");
  const witnessPath = path.join(ctx.workDir, "witness.wtns");
  const proofPath = path.join(ctx.workDir, "proof.json");
  const publicPath = path.join(ctx.workDir, "public.json");

  writeJson(inputPath, input);

  const witnessRun = timedCommand(ctx, buildNodeCommand(ctx, [
    ctx.config.artifacts.witnessGenerator,
    ctx.config.artifacts.wasm,
    inputPath,
    witnessPath,
  ]));

  const proveRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "groth16",
    "prove",
    ctx.config.artifacts.zkey,
    witnessPath,
    proofPath,
    publicPath,
  ]));

  const verifyRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "groth16",
    "verify",
    ctx.config.artifacts.vkey,
    publicPath,
    proofPath,
  ]));

  const proofObj = readJson(proofPath);
  const publicObj = readJson(publicPath);
  const createdAt = Date.now();
  const record = {
    created_at: createdAt,
    scheme: "Groth16",
    circuit: ctx.config.circuitId,
    signer_label: signed.signer_label,
    signed_message_file: messageFile,
    msg_text_utf8: signed.msg_text_utf8,
    masked_display_text: redaction.maskedDisplayText,
    masked_control_text: redaction.maskedControlText,
    masked_hex: redaction.maskedHex,
    redaction_ranges: redaction.ranges,
    public_inputs: publicObj,
    proof: proofObj,
    public_summary: signed.public_summary || "",
    proof_public_meta: ctx.config.proofPublicMeta ? ctx.config.proofPublicMeta(signed) : {},
    timings: {
      witness_ms: witnessRun.ms,
      prove_ms: proveRun.ms,
      verify_ms: verifyRun.ms,
      total_ms: witnessRun.ms + proveRun.ms + verifyRun.ms,
    },
  };

  const file = "proof_" + signed.signer_label + "_" + createdAt + ".json";
  writeJson(path.join(ctx.proofDir, file), record);

  return {
    ok: true,
    proof: summarizeProof(file, record),
  };
}

async function verifyStoredProof(ctx, body) {
  await ensureArtifacts(ctx);

  const proofFile = body && body.proof_file ? body.proof_file : "";
  if (!proofFile) {
    throw new Error("Choose a proof first.");
  }

  const proofPath = path.join(ctx.proofDir, proofFile);
  if (!fs.existsSync(proofPath)) {
    throw new Error("Proof not found.");
  }

  const record = readJson(proofPath);
  resetWorkDir(ctx);

  const workProof = path.join(ctx.workDir, "proof.json");
  const workPublic = path.join(ctx.workDir, "public.json");
  writeJson(workProof, record.proof);
  writeJson(workPublic, record.public_inputs);

  const verifyRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "groth16",
    "verify",
    ctx.config.artifacts.vkey,
    workPublic,
    workProof,
  ]));

  record.timings = record.timings || {};
  record.timings.latest_verify_ms = verifyRun.ms;
  writeJson(proofPath, record);

  return {
    ok: true,
    proof: summarizeProof(proofFile, record),
  };
}

async function exportProofBundle(ctx, body) {
  await ensureArtifacts(ctx);

  const proofFile = body && body.proof_file ? body.proof_file : "";
  if (!proofFile) {
    throw new Error("Choose a proof first.");
  }

  const proofPath = path.join(ctx.proofDir, proofFile);
  if (!fs.existsSync(proofPath)) {
    throw new Error("Proof not found.");
  }

  const record = readJson(proofPath);
  const buildInfo = fs.existsSync(ctx.buildInfoPath) ? readJson(ctx.buildInfoPath) : null;
  const suggested = "bundle_" + record.signer_label + "_" + Date.now();
  const bundleName = sanitizeLabel(body && body.bundle_name) || suggested;
  const archiveName = bundleName + ".zip";
  const bundleDir = path.join(ctx.downloadDir, bundleName);
  const archivePath = path.join(ctx.downloadDir, archiveName);
  const circuitDir = path.join(bundleDir, "circuit");
  const circuitSourcePath = path.join(ctx.rootDir, ctx.config.circuitFile);
  const sharedHelperPath = path.join(ctx.rootDir, "redaction_helpers.circom");
  const meta = {
    created_at: Date.now(),
    algorithm_id: ctx.config.algorithmId,
    signer_label: record.signer_label,
    circuit: record.circuit,
    scheme: record.scheme,
    masked_control_text: record.masked_control_text,
    masked_display_text: record.masked_display_text,
    public_summary: record.public_summary || "",
    proof_public_meta: record.proof_public_meta || {},
    redaction_ranges: record.redaction_ranges || [],
    redaction_sentinel: REDACTION_SENTINEL,
    timings: record.timings || {},
  };

  removeDirSync(bundleDir);
  removeFileSync(archivePath);
  fs.mkdirSync(circuitDir, { recursive: true });

  writeJson(path.join(bundleDir, "proof.json"), record.proof);
  writeJson(path.join(bundleDir, "public.json"), record.public_inputs);
  writeJson(path.join(bundleDir, "meta.json"), meta);
  copyFile(ctx.config.artifacts.vkey, path.join(bundleDir, "verification_key.json"));
  copyFile(circuitSourcePath, path.join(circuitDir, path.basename(circuitSourcePath)));
  copyFile(ctx.config.artifacts.r1cs, path.join(circuitDir, path.basename(ctx.config.artifacts.r1cs)));
  if (fs.existsSync(sharedHelperPath)) {
    copyFile(sharedHelperPath, path.join(circuitDir, path.basename(sharedHelperPath)));
  }
  if (buildInfo) {
    writeJson(path.join(bundleDir, "build_info.json"), buildInfo);
  }

  writeTextFile(path.join(bundleDir, "README.md"), buildProofBundleReadme(ctx, record, buildInfo));

  const checksumFiles = [
    "README.md",
    "meta.json",
    "proof.json",
    "public.json",
    "verification_key.json",
    path.posix.join("circuit", path.basename(circuitSourcePath)),
    path.posix.join("circuit", path.basename(ctx.config.artifacts.r1cs)),
  ];
  if (fs.existsSync(sharedHelperPath)) {
    checksumFiles.push(path.posix.join("circuit", path.basename(sharedHelperPath)));
  }
  if (buildInfo) {
    checksumFiles.push("build_info.json");
  }
  checksumFiles.sort();
  writeTextFile(path.join(bundleDir, "checksums.sha256"), buildChecksumFile(bundleDir, checksumFiles));

  createZipArchive(ctx, bundleDir, archivePath);
  removeDirSync(bundleDir);

  return {
    ok: true,
    bundle_name: bundleName,
    archive_name: archiveName,
    download_url: "/api/download?name=" + encodeURIComponent(archiveName),
  };
}

async function resetState(ctx) {
  removeDirSync(ctx.keyDir);
  removeDirSync(ctx.messageDir);
  removeDirSync(ctx.proofDir);
  removeDirSync(ctx.publicDir);
  removeDirSync(ctx.downloadDir);
  ensureDirs(ctx);
  return { ok: true };
}

async function ensureArtifacts(ctx) {
  if (!artifactsExist(ctx)) {
    await rebuildArtifacts(ctx);
  }
}

function artifactsExist(ctx) {
  return fs.existsSync(ctx.config.artifacts.wasm) &&
    fs.existsSync(ctx.config.artifacts.witnessGenerator) &&
    fs.existsSync(ctx.config.artifacts.zkey) &&
    fs.existsSync(ctx.config.artifacts.vkey) &&
    fs.existsSync(ctx.config.artifacts.r1cs);
}

async function rebuildArtifacts(ctx) {
  ensureProjectDependencies(ctx);

  fs.mkdirSync(ctx.buildDir, { recursive: true });

  const compileRun = timedCommand(ctx, buildCircomCommand(ctx));
  const r1csInfoRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "r1cs",
    "info",
    ctx.config.artifacts.r1cs,
  ]));

  const constraints = parseConstraintCount(r1csInfoRun.stdout + "\n" + r1csInfoRun.stderr);
  const ptauPower = Math.max(12, ceilLog2(constraints + 1));
  const ptau0 = path.join(ctx.buildDir, "pot" + ptauPower + "_0000.ptau");
  const ptau1 = path.join(ctx.buildDir, "pot" + ptauPower + "_0001.ptau");
  const ptauFinal = path.join(ctx.buildDir, "pot" + ptauPower + "_final.ptau");
  const zkey0 = path.join(ctx.buildDir, "circuit_0000.zkey");

  let ptauMs = 0;
  if (!fs.existsSync(ptauFinal)) {
    ptauMs += timedCommand(ctx, buildSnarkjsCommand(ctx, [
      "powersoftau",
      "new",
      "bn128",
      String(ptauPower),
      ptau0,
    ])).ms;

    ptauMs += timedCommand(ctx, buildSnarkjsCommand(ctx, [
      "powersoftau",
      "contribute",
      ptau0,
      ptau1,
      "--name=demo",
      "-e=redacted-zkp-demo",
    ])).ms;

    ptauMs += timedCommand(ctx, buildSnarkjsCommand(ctx, [
      "powersoftau",
      "prepare",
      "phase2",
      ptau1,
      ptauFinal,
    ])).ms;
  }

  const setupRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "groth16",
    "setup",
    ctx.config.artifacts.r1cs,
    ptauFinal,
    zkey0,
  ]));

  const contributeRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "zkey",
    "contribute",
    zkey0,
    ctx.config.artifacts.zkey,
    "--name=demo",
    "-e=redacted-zkp-demo-zkey",
  ]));

  const vkeyRun = timedCommand(ctx, buildSnarkjsCommand(ctx, [
    "zkey",
    "export",
    "verificationkey",
    ctx.config.artifacts.zkey,
    ctx.config.artifacts.vkey,
  ]));

  const buildInfo = {
    created_at: Date.now(),
    constraints: constraints,
    ptau_power: ptauPower,
    timings: {
      compile_ms: compileRun.ms,
      r1cs_info_ms: r1csInfoRun.ms,
      ptau_ms: ptauMs,
      groth16_setup_ms: setupRun.ms,
      zkey_contribute_ms: contributeRun.ms,
      export_vkey_ms: vkeyRun.ms,
      total_ms: compileRun.ms + r1csInfoRun.ms + ptauMs + setupRun.ms + contributeRun.ms + vkeyRun.ms,
    },
  };

  writeJson(ctx.buildInfoPath, buildInfo);

  return {
    ok: true,
    build_info: buildInfo,
  };
}

function ensureProjectDependencies(ctx) {
  const nodeModulesDir = path.join(ctx.rootDir, "node_modules");
  if (!fs.existsSync(nodeModulesDir)) {
    timedCommand(ctx, "npm install");
  }
}

function buildCircomCommand(ctx) {
  const args = ["circom", ctx.config.circuitFile];
  for (let i = 0; i < ctx.config.circomArgs.length; i++) {
    args.push(ctx.config.circomArgs[i]);
  }
  return args.join(" ");
}

function buildNodeCommand(ctx, args) {
  return "node " + args.map(shellQuote).join(" ");
}

function buildSnarkjsCommand(ctx, args) {
  const base = resolveSnarkjsBaseCommand(ctx);
  return base + " " + args.map(shellQuote).join(" ");
}

function resolveSnarkjsBaseCommand(ctx) {
  if (ctx.snarkjsBaseCommand) {
    return ctx.snarkjsBaseCommand;
  }

  const globalRoot = runShell(ctx, "npm root -g", ctx.rootDir);
  const cliPath = path.join(globalRoot.stdout.trim(), "snarkjs", "build", "cli.cjs");
  if (fs.existsSync(cliPath)) {
    ctx.snarkjsBaseCommand = "npm exec --yes --package=node@20 -- node " + shellQuote(cliPath);
    return ctx.snarkjsBaseCommand;
  }

  if (commandWorks(ctx, "snarkjs g16v --help")) {
    ctx.snarkjsBaseCommand = "snarkjs";
    return ctx.snarkjsBaseCommand;
  }

  throw new Error("snarkjs is not available. Install it in WSL or expose a working PATH.");
}

function commandWorks(ctx, command) {
  const result = spawnSync("bash", ["-lc", command], {
    cwd: ctx.rootDir,
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 1024 * 1024 * 32,
  });
  return result.status === 0;
}

function timedCommand(ctx, command) {
  const result = runShell(ctx, command, ctx.rootDir);
  return {
    ms: result.ms,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

function runShell(ctx, command, cwd) {
  const effectiveCwd = cwd || ctx.rootDir;
  console.log("[cmd] --> (" + effectiveCwd + ") " + command);
  const started = process.hrtime.bigint();
  const result = spawnSync("bash", ["-lc", command], {
    cwd: effectiveCwd,
    encoding: "utf8",
    timeout: 0,
    maxBuffer: 1024 * 1024 * 64,
  });
  const ms = Math.round(Number(process.hrtime.bigint() - started) / 1000000);

  console.log("[cmd] <-- exit " + String(result.status) + " in " + ms + "ms");
  console.log("[cmd][stdout]");
  console.log(result.stdout ? result.stdout.trimEnd() : "<empty>");
  console.log("[cmd][stderr]");
  console.log(result.stderr ? result.stderr.trimEnd() : "<empty>");

  if (result.status !== 0) {
    throw new Error(buildCommandError(command, result));
  }

  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    ms: ms,
  };
}

function buildCommandError(command, result) {
  const parts = [];
  parts.push("Command failed: " + command);
  if (result.stdout) {
    parts.push(result.stdout.trim());
  }
  if (result.stderr) {
    parts.push(result.stderr.trim());
  }
  return parts.filter(Boolean).join("\n");
}

function buildCompressedRedaction(text, msgBytesRaw, msgLen, rangesInput) {
  const safeTextInfo = truncateUtf8Text(text, MAX_MESSAGE_BYTES);
  const safeText = safeTextInfo.text;
  const msgBytes = msgBytesRaw.map(function (value) {
    return Number(value);
  });
  const ranges = normalizeRanges(rangesInput, safeText.length);
  const charByteOffsets = buildCharByteOffsets(safeText);
  const hidden = new Array(MAX_MESSAGE_BYTES).fill(false);

  for (let i = 0; i < ranges.length; i++) {
    const range = ranges[i];
    const startByte = charByteOffsets[range.start];
    const endByte = charByteOffsets[range.end];
    for (let byteIndex = startByte; byteIndex < endByte; byteIndex++) {
      hidden[byteIndex] = true;
    }
  }

  const reveal = new Array(MAX_MESSAGE_BYTES).fill(0);
  const maskedBytes = [];

  for (let i = 0; i < msgLen; i++) {
    if (!hidden[i]) {
      if (msgBytes[i] === 0 || msgBytes[i] === REDACTION_SENTINEL) {
        throw new Error(
          "Visible message bytes cannot include 0x00 or " +
          toHexLiteral(REDACTION_SENTINEL) +
          " because they are reserved for padding/control markers in the compressed public redaction."
        );
      }
      reveal[i] = 1;
      maskedBytes.push(msgBytes[i]);
      continue;
    }

    if (i === 0 || !hidden[i - 1]) {
      maskedBytes.push(REDACTION_SENTINEL);
    }
  }

  const paddedMasked = new Array(MAX_MESSAGE_BYTES).fill(0);
  for (let i = 0; i < Math.min(maskedBytes.length, MAX_MESSAGE_BYTES); i++) {
    paddedMasked[i] = maskedBytes[i];
  }

  return {
    ranges: ranges,
    reveal: reveal.map(String),
    masked: paddedMasked.map(String),
    maskedBytes: maskedBytes,
    maskedHex: maskedBytes.map(toHexByte).join(" "),
    maskedDisplayText: renderMaskedDisplayText(safeText, ranges),
    maskedControlText: renderMaskedControlText(safeText, ranges),
  };
}

function renderMaskedDisplayText(text, ranges) {
  if (ranges.length === 0) {
    return text;
  }

  let cursor = 0;
  const pieces = [];
  for (let i = 0; i < ranges.length; i++) {
    const range = ranges[i];
    if (cursor < range.start) {
      pieces.push(text.slice(cursor, range.start));
    }
    pieces.push("[REDACTED]");
    cursor = range.end;
  }
  if (cursor < text.length) {
    pieces.push(text.slice(cursor));
  }
  return pieces.join("");
}

function renderMaskedControlText(text, ranges) {
  if (ranges.length === 0) {
    return text;
  }

  let cursor = 0;
  const pieces = [];
  for (let i = 0; i < ranges.length; i++) {
    const range = ranges[i];
    if (cursor < range.start) {
      pieces.push(text.slice(cursor, range.start));
    }
    pieces.push("\\x01");
    cursor = range.end;
  }
  if (cursor < text.length) {
    pieces.push(text.slice(cursor));
  }
  return pieces.join("");
}

function normalizeRanges(rangesInput, textLength) {
  const ranges = Array.isArray(rangesInput) ? rangesInput.slice() : [];
  const normalized = [];

  for (let i = 0; i < ranges.length; i++) {
    const raw = ranges[i] || {};
    const start = clampInt(raw.start, 0, textLength);
    const end = clampInt(raw.end, 0, textLength);
    const a = Math.min(start, end);
    const b = Math.max(start, end);
    if (a !== b) {
      normalized.push({ start: a, end: b });
    }
  }

  normalized.sort(function (left, right) {
    if (left.start !== right.start) return left.start - right.start;
    return left.end - right.end;
  });

  const merged = [];
  for (let i = 0; i < normalized.length; i++) {
    const current = normalized[i];
    if (merged.length === 0) {
      merged.push(current);
      continue;
    }

    const previous = merged[merged.length - 1];
    if (current.start <= previous.end) {
      previous.end = Math.max(previous.end, current.end);
    } else {
      merged.push(current);
    }
  }

  return merged;
}

function buildCharByteOffsets(text) {
  const offsets = new Array(text.length + 1);
  let running = 0;
  let index = 0;

  offsets[0] = 0;

  while (index < text.length) {
    const codePoint = text.codePointAt(index);
    const ch = String.fromCodePoint(codePoint);
    running += Buffer.byteLength(ch, "utf8");

    if (codePoint > 0xffff) {
      offsets[index + 1] = running;
      offsets[index + 2] = running;
      index += 2;
    } else {
      offsets[index + 1] = running;
      index += 1;
    }
  }

  return offsets;
}

function truncateUtf8Text(text, limit) {
  const source = typeof text === "string" ? text : "";
  let out = "";
  let bytes = 0;

  for (const ch of source) {
    const charBytes = Buffer.byteLength(ch, "utf8");
    if (bytes + charBytes > limit) {
      break;
    }
    out += ch;
    bytes += charBytes;
  }

  const buffer = Buffer.from(out, "utf8");
  const padded = Buffer.alloc(limit, 0);
  buffer.copy(padded);

  return {
    text: out,
    msgLen: buffer.length,
    bytes: Array.from(padded, function (value) { return value; }),
  };
}

function parseConstraintCount(output) {
  const match = output.match(/constraints:\s*([0-9,]+)/i) || output.match(/# of Constraints:\s*([0-9,]+)/i);
  if (!match) {
    throw new Error("Could not parse circuit constraint count from snarkjs output.");
  }
  return parseInt(match[1].replace(/,/g, ""), 10);
}

function ceilLog2(value) {
  let power = 0;
  let current = 1;
  while (current < value) {
    current *= 2;
    power += 1;
  }
  return power;
}

function resetWorkDir(ctx) {
  removeDirSync(ctx.workDir);
  fs.mkdirSync(ctx.workDir, { recursive: true });
}

function removeDirSync(pathname) {
  if (!fs.existsSync(pathname)) {
    return;
  }

  if (typeof fs.rmSync === "function") {
    fs.rmSync(pathname, { recursive: true, force: true });
    return;
  }

  fs.rmdirSync(pathname, { recursive: true });
}

function nextAutoLabel(ctx) {
  const used = listJsonFiles(ctx.keyDir).map(function (file) {
    return path.basename(file, ".json");
  });

  const pool = [
    "ALICE", "BOB", "CHARLIE", "DAVID", "EVE", "FRANK",
    "GRACE", "HEIDI", "IVAN", "JUDY", "MALLORY", "NIA",
    "OLIVIA", "PEGGY", "SYBIL", "TRENT", "VICTOR", "WALTER",
  ];

  for (let i = 0; i < pool.length; i++) {
    if (used.indexOf(pool[i]) === -1) {
      return pool[i];
    }
  }

  return "SIGNER_" + Date.now();
}

function sanitizeLabel(label) {
  if (!label) return "";
  return String(label).trim().replace(/[^\w\-]/g, "_");
}

function clampInt(value, min, max) {
  const parsed = parseInt(value, 10);
  if (Number.isNaN(parsed)) return min;
  return Math.max(min, Math.min(max, parsed));
}

function toHexByte(value) {
  return value.toString(16).padStart(2, "0");
}

function toHexLiteral(value) {
  return "0x" + toHexByte(value);
}

function listJsonFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(function (name) {
    return name.endsWith(".json");
  });
}

function listDirectories(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).filter(function (entry) {
    return entry.isDirectory();
  }).map(function (entry) {
    return entry.name;
  });
}

function readJson(pathname) {
  return JSON.parse(fs.readFileSync(pathname, "utf8"));
}

function writeJson(pathname, value) {
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, JSON.stringify(value, null, 2));
}

function writeTextFile(pathname, value) {
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(pathname, value, "utf8");
}

function buildProofBundleReadme(ctx, record, buildInfo) {
  const circuitSourceName = path.basename(ctx.config.circuitFile);
  const r1csName = path.basename(ctx.config.artifacts.r1cs);
  const publicInputsSummary = "The public inputs expose the masked message bytes, the RSA modulus, and the RSA public exponent.";
  const lines = [
    "# Proof Bundle",
    "",
    "This archive contains one exported Groth16 proof together with the verification key and the exact compiled circuit snapshot used by the demo.",
    "",
    "## Quick Verification",
    "1. Verify every file hash with `sha256sum -c checksums.sha256`.",
    "2. Compare the hash of `circuit/" + r1csName + "` in `checksums.sha256` with the hash published in the repo or paper.",
    "3. Verify the proof itself with `snarkjs groth16 verify verification_key.json public.json proof.json`.",
    "4. Treat the proof as trustworthy only when both the hashes match the published circuit snapshot and `snarkjs` reports `OK!`.",
    "",
    "## What The Circuit Proves",
    "- The public masked message is consistent with a valid original message, using `0x01` as the start marker for each hidden run.",
    "- The signature is checked against the full original message, not just the revealed text.",
    "- The hidden message bytes and the hash of the original message remain private witness data and are not exposed in `public.json`.",
    "- " + publicInputsSummary,
    "",
    "## Files",
    "- `proof.json`: the Groth16 proof.",
    "- `public.json`: the public inputs consumed by the verifier.",
    "- `verification_key.json`: the Groth16 verification key.",
    "- `meta.json`: human-readable context, masked preview text, and timing metadata.",
    "- `checksums.sha256`: SHA-256 digests for the files in this bundle.",
    "- `circuit/" + circuitSourceName + "`: the top-level Circom source.",
    "- `circuit/redaction_helpers.circom`: the shared compressed-redaction helper used by the circuit.",
    "- `circuit/" + r1csName + "`: the compiled constraint system for hashing and independent inspection.",
  ];

  if (buildInfo) {
    lines.push("- `build_info.json`: compile and setup telemetry recorded by the demo.");
  }

  lines.push(
    "",
    "## Manual Verification",
    "If `sha256sum` and `snarkjs` are installed, run:",
    "",
    "```bash",
    "sha256sum -c checksums.sha256",
    "sha256sum circuit/" + r1csName,
    "snarkjs groth16 verify verification_key.json public.json proof.json",
    "```",
    "",
    "The `sha256sum circuit/" + r1csName + "` output should match the digest published for the compiled circuit, and the proof is valid only if the `snarkjs` command returns `OK!`."
  );

  return lines.join("\n") + "\n";
}

function buildChecksumFile(rootDir, relativePaths) {
  return relativePaths.map(function (relativePath) {
    const normalized = relativePath.replace(/\\/g, "/");
    return hashFileSha256(path.join(rootDir, normalized)) + "  " + normalized;
  }).join("\n") + "\n";
}

function hashFileSha256(pathname) {
  return crypto.createHash("sha256").update(fs.readFileSync(pathname)).digest("hex");
}

function createZipArchive(ctx, sourceDir, archivePath) {
  runShell(ctx, "zip -X -rq " + shellQuote(archivePath) + " .", sourceDir);
}

function removeFileSync(pathname) {
  if (fs.existsSync(pathname)) {
    fs.unlinkSync(pathname);
  }
}

function copyFile(source, target) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
}

function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
}

function serveFile(res, pathname, contentType) {
  const content = fs.readFileSync(pathname);
  res.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  res.end(content);
}

function serveDownloadArchive(ctx, res, name) {
  const safeName = path.basename(String(name || ""));
  if (!safeName || safeName !== name) {
    throw new Error("Invalid download name.");
  }

  const archivePath = path.join(ctx.downloadDir, safeName);
  if (!fs.existsSync(archivePath)) {
    throw new Error("Download not found.");
  }

  return streamDownloadFile(res, archivePath, "application/zip", safeName);
}

function streamDownloadFile(res, pathname, contentType, downloadName) {
  return new Promise(function (resolve, reject) {
    const stat = fs.statSync(pathname);
    const stream = fs.createReadStream(pathname);

    stream.on("error", reject);
    stream.on("end", resolve);

    res.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": stat.size,
      "Content-Disposition": "attachment; filename=\"" + String(downloadName).replace(/\"/g, "") + "\"",
      "Cache-Control": "no-store",
    });

    stream.pipe(res);
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload, null, 2));
}

function readJsonBody(req) {
  return new Promise(function (resolve, reject) {
    let body = "";

    req.on("data", function (chunk) {
      body += chunk.toString("utf8");
      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large."));
      }
    });

    req.on("end", function () {
      if (!body) {
        logRequestBody(req, {});
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(body);
        logRequestBody(req, parsed);
        resolve(parsed);
      } catch (err) {
        console.error("[http] !! invalid JSON " + req.method + " " + req.url);
        console.error(body);
        reject(new Error("Invalid JSON body."));
      }
    });

    req.on("error", reject);
  });
}

module.exports = {
  MAX_MESSAGE_BYTES,
  REDACTION_SENTINEL,
  startDemo,
  truncateUtf8Text,
};

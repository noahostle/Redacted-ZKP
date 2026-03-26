(function () {
  const state = {
    config: null,
    data: null,
    selectedMessageFile: "",
    ranges: [],
  };

  const elements = {
    title: document.getElementById("demo-title"),
    sentinelByte: document.getElementById("sentinel-byte"),
    maxBytes: document.getElementById("max-bytes"),
    signerSelect: document.getElementById("signer-select"),
    signerHint: document.getElementById("signer-hint"),
    newSignerLabel: document.getElementById("new-signer-label"),
    messageInput: document.getElementById("message-input"),
    messagesList: document.getElementById("messages-list"),
    redactionSource: document.getElementById("redaction-source"),
    redactionRanges: document.getElementById("redaction-ranges"),
    maskedDisplayPreview: document.getElementById("masked-display-preview"),
    maskedControlPreview: document.getElementById("masked-control-preview"),
    proofsList: document.getElementById("proofs-list"),
    statusText: document.getElementById("status-text"),
  };

  bindEvents();
  boot().catch(handleError);

  function bindEvents() {
    document.getElementById("rebuild-button").addEventListener("click", rebuildCircuit);
    document.getElementById("create-signer-button").addEventListener("click", createSigner);
    document.getElementById("sign-message-button").addEventListener("click", signMessage);
    document.getElementById("redact-selection-button").addEventListener("click", addSelectionRedaction);
    document.getElementById("undo-redaction-button").addEventListener("click", undoRedaction);
    document.getElementById("clear-redactions-button").addEventListener("click", clearRedactions);
    document.getElementById("generate-proof-button").addEventListener("click", generateProof);
    document.getElementById("reset-state-button").addEventListener("click", resetState);
    elements.signerSelect.addEventListener("change", renderSignerHint);
  }

  async function boot() {
    setStatus("Loading demo state...");
    state.config = await apiGet("/api/config");
    elements.title.textContent = state.config.demoTitle;
    elements.sentinelByte.textContent = "0x" + state.config.redactionSentinel.toString(16).padStart(2, "0");
    elements.maxBytes.textContent = state.config.maxMessageBytes + " bytes";
    await refreshState();
    setStatus("Ready!");
  }

  async function refreshState() {
    state.data = await apiGet("/api/state");
    render();
  }

  function render() {
    renderSigners();
    renderMessages();
    renderWorkspace();
    renderProofs();
  }

  function renderSigners() {
    const signers = state.data.signers || [];
    const previousSelection = elements.signerSelect.value;
    const options = ["<option value=''>Select a signer...</option>"];
    signers.forEach(function (signer) {
      options.push("<option value='" + escapeAttr(signer.label) + "'>" + escapeHtml(signer.label) + "</option>");
    });
    elements.signerSelect.innerHTML = options.join("");
    if (findSigner(previousSelection)) {
      elements.signerSelect.value = previousSelection;
    }
    renderSignerHint();
  }

  function renderSignerHint() {
    const selected = findSigner(elements.signerSelect.value);
    if (!selected) {
      elements.signerHint.classList.add("empty-state");
      elements.signerHint.textContent = "Create or choose a signer to sign a message.";
      return;
    }

    elements.signerHint.classList.remove("empty-state");
    elements.signerHint.innerHTML = [
      signerDetailLine("Selected Signer", selected.label || "Unavailable"),
      signerDetailLine("Signature Scheme", selected.signature_scheme || "Unavailable"),
      signerDetailLine("Keypair type", selected.keypair_type || "Unavailable"),
      signerDetailLine("e", selected.public_exponent || "Unavailable"),
      signerDetailLine("Public Modulus n", selected.modulus_hex || "Unavailable", " signer-detail-value-modulus"),
    ].join("");
  }

  function renderMessages() {
    const messages = state.data.messages || [];
    if (messages.length === 0) {
      elements.messagesList.innerHTML = "<div class='message-card empty-state'>No signed messages yet.</div>";
      return;
    }

    elements.messagesList.innerHTML = messages.map(function (message) {
      const active = message.file === state.selectedMessageFile ? " style='border-color: rgba(15, 122, 108, 0.5)'" : "";
      return [
        "<div class='message-card'" + active + ">",
        "  <div class='card-row'>",
        "    <div>",
        "      <h3 class='card-title'>" + escapeHtml(message.signer_label) + "</h3>",
        "      <p class='excerpt'>" + escapeHtml(message.msg_text_utf8 || "") + "</p>",
        "      <p class='subtle-text'>Signature Preview: " + escapeHtml(message.signature_preview || "Unavailable") + "</p>",
        "      <p class='subtle-text'>" + escapeHtml(message.public_summary || "") + "</p>",
        "    </div>",
        "    <div class='toolbar'>",
        "      <button class='button' data-action='select-message' data-file='" + escapeAttr(message.file) + "'>Use For Redaction</button>",
        "    </div>",
        "  </div>",
        "</div>",
      ].join("");
    }).join("");

    attachActionButtons(elements.messagesList);
  }

  function renderWorkspace() {
    const message = findMessage(state.selectedMessageFile);
    if (!message) {
      elements.redactionSource.value = "";
      elements.maskedDisplayPreview.innerHTML = "No message selected.";
      elements.maskedDisplayPreview.classList.add("empty-state");
      elements.maskedControlPreview.textContent = "Select text and press “Redact Selection”.";
      elements.redactionRanges.innerHTML = "";
      return;
    }

    elements.redactionSource.value = message.msg_text_utf8 || "";
    const preview = buildPreview(message.msg_text_utf8 || "", state.ranges);
    elements.maskedDisplayPreview.classList.remove("empty-state");
    elements.maskedDisplayPreview.innerHTML = preview.displayHtml;
    elements.maskedControlPreview.textContent = preview.controlText || "(empty)";
    elements.redactionRanges.innerHTML = state.ranges.length === 0
      ? "<span class='subtle-text'>No redactions yet. Highlight text in the source field and press “Redact Selection”.</span>"
      : state.ranges.map(function (range, index) {
          const snippet = (message.msg_text_utf8 || "").slice(range.start, range.end);
          return "<span class='redaction-chip'>#" + (index + 1) + " " + escapeHtml(snippet) + "</span>";
        }).join("");
  }

  function renderProofs() {
    const proofs = state.data.proofs || [];
    if (proofs.length === 0) {
      elements.proofsList.innerHTML = "<div class='proof-card empty-state'>No proofs yet.</div>";
      return;
    }

    elements.proofsList.innerHTML = proofs.map(function (proof) {
      const timings = proof.timings || {};
      return [
        "<div class='proof-card'>",
        "  <div class='card-row'>",
        "    <div>",
        "      <h3 class='card-title'>" + escapeHtml(proof.signer_label) + "</h3>",
        "      <p class='excerpt'>" + escapeHtml(proof.masked_display_text || proof.masked_control_text || "") + "</p>",
        "      <p class='subtle-text'>" + escapeHtml(proof.public_summary || "") + "</p>",
        "    </div>",
        "    <div class='toolbar'>",
        "      <button class='button' data-action='verify-proof' data-file='" + escapeAttr(proof.file) + "'>Verify</button>",
        "      <button class='button button-ghost' data-action='export-proof' data-file='" + escapeAttr(proof.file) + "'>Export</button>",
        "    </div>",
        "  </div>",
        "  <div class='timing-grid'>",
        tile("Witness", timings.witness_ms),
        tile("Prove", timings.prove_ms),
        tile("Verify", timings.verify_ms || timings.latest_verify_ms),
        tile("Total", timings.total_ms),
        "  </div>",
        "</div>",
      ].join("");
    }).join("");

    attachActionButtons(elements.proofsList);
  }

  function attachActionButtons(container) {
    Array.prototype.forEach.call(container.querySelectorAll("[data-action]"), function (button) {
      button.addEventListener("click", handleActionButton);
    });
  }

  async function handleActionButton(event) {
    const button = event.currentTarget;
    const action = button.getAttribute("data-action");
    const file = button.getAttribute("data-file");

    try {
      if (action === "select-message") {
        state.selectedMessageFile = file;
        state.ranges = [];
        renderWorkspace();
        setStatus("Loaded signed message into the redaction workspace.");
        return;
      }

      if (action === "verify-proof") {
        setStatus("Verifying proof...");
        await apiPost("/api/verify", { proof_file: file });
        await refreshState();
        setStatus("Proof verified successfully.");
        return;
      }

      if (action === "export-proof") {
        setStatus("Exporting proof bundle...");
        const response = await apiPost("/api/export", { proof_file: file });
        await downloadFile(response.download_url, response.archive_name);
        setStatus("Proof bundle downloaded.");
      }
    } catch (error) {
      handleError(error);
    }
  }

  async function rebuildCircuit() {
    if (!window.confirm("Are you sure? this step is only necessary for circuit verification and can take a while...")) {
      return;
    }

    try {
      setStatus("Rebuilding circuit and Groth16 artifacts...");
      await apiPost("/api/build", {});
      await refreshState();
      setStatus("Circuit rebuild finished.");
    } catch (error) {
      handleError(error);
    }
  }

  async function createSigner() {
    try {
      const label = elements.newSignerLabel.value.trim();
      setStatus("Creating signer...");
      const response = await apiPost("/api/signers", { label: label });
      elements.newSignerLabel.value = "";
      await refreshState();
      elements.signerSelect.value = response.signer.label;
      renderSignerHint();
      setStatus("Signer created: " + response.signer.label);
    } catch (error) {
      handleError(error);
    }
  }

  async function signMessage() {
    try {
      const signerLabel = elements.signerSelect.value;
      const text = elements.messageInput.value;
      setStatus("Signing message...");
      const response = await apiPost("/api/messages", {
        signer_label: signerLabel,
        text: text,
      });
      elements.messageInput.value = "";
      await refreshState();
      state.selectedMessageFile = response.message.file;
      state.ranges = [];
      renderWorkspace();
      setStatus("Signed message saved and loaded into the workspace.");
    } catch (error) {
      handleError(error);
    }
  }

  function addSelectionRedaction() {
    const source = elements.redactionSource;
    if (!state.selectedMessageFile) {
      handleError(new Error("Choose a signed message first."));
      return;
    }

    const start = source.selectionStart;
    const end = source.selectionEnd;
    if (start === end) {
      handleError(new Error("Select some text in the source field before redacting."));
      return;
    }

    state.ranges = normalizeRanges(state.ranges.concat([{ start: start, end: end }]), source.value.length);
    renderWorkspace();
    setStatus("Selection redacted. You can keep adding more spans before generating the proof.");
  }

  function undoRedaction() {
    if (state.ranges.length === 0) {
      return;
    }
    state.ranges = state.ranges.slice(0, state.ranges.length - 1);
    renderWorkspace();
    setStatus("Removed the last redaction.");
  }

  function clearRedactions() {
    state.ranges = [];
    renderWorkspace();
    setStatus("Cleared all redactions for the current message.");
  }

  async function generateProof() {
    if (!state.selectedMessageFile) {
      handleError(new Error("Choose a signed message first."));
      return;
    }

    try {
      setStatus("Generating witness, proof, and verification timings...");
      await apiPost("/api/proofs", {
        message_file: state.selectedMessageFile,
        ranges: state.ranges,
      });
      await refreshState();
      setStatus("Proof generated successfully.");
    } catch (error) {
      handleError(error);
    }
  }

  async function resetState() {
    if (!window.confirm("Delete all saved signers, messages, proofs, and downloaded bundle staging files?")) {
      return;
    }

    try {
      setStatus("Resetting demo state...");
      await apiPost("/api/reset", {});
      state.selectedMessageFile = "";
      state.ranges = [];
      await refreshState();
      setStatus("Demo state cleared.");
    } catch (error) {
      handleError(error);
    }
  }

  function buildPreview(text, ranges) {
    if (!text) {
      return {
        displayHtml: "<span class='empty-state'>No message selected.</span>",
        controlText: "",
      };
    }

    const merged = normalizeRanges(ranges, text.length);
    if (merged.length === 0) {
      return {
        displayHtml: escapeHtml(text),
        controlText: text,
      };
    }

    let cursor = 0;
    const displayPieces = [];
    const controlPieces = [];
    merged.forEach(function (range) {
      if (cursor < range.start) {
        const visible = text.slice(cursor, range.start);
        displayPieces.push(escapeHtml(visible));
        controlPieces.push(visible);
      }
      displayPieces.push("<span class='masked-chip'>REDACTED</span>");
      controlPieces.push("\\x01");
      cursor = range.end;
    });
    if (cursor < text.length) {
      const tail = text.slice(cursor);
      displayPieces.push(escapeHtml(tail));
      controlPieces.push(tail);
    }

    return {
      displayHtml: displayPieces.join(""),
      controlText: controlPieces.join(""),
    };
  }

  function normalizeRanges(ranges, textLength) {
    const cleaned = ranges.map(function (range) {
      const start = clamp(range.start, 0, textLength);
      const end = clamp(range.end, 0, textLength);
      return {
        start: Math.min(start, end),
        end: Math.max(start, end),
      };
    }).filter(function (range) {
      return range.start !== range.end;
    }).sort(function (a, b) {
      if (a.start !== b.start) return a.start - b.start;
      return a.end - b.end;
    });

    const merged = [];
    cleaned.forEach(function (range) {
      if (merged.length === 0) {
        merged.push(range);
        return;
      }
      const last = merged[merged.length - 1];
      if (range.start <= last.end) {
        last.end = Math.max(last.end, range.end);
      } else {
        merged.push(range);
      }
    });
    return merged;
  }

  function findMessage(file) {
    return (state.data.messages || []).find(function (message) {
      return message.file === file;
    }) || null;
  }

  function findSigner(label) {
    return (state.data.signers || []).find(function (signer) {
      return signer.label === label;
    }) || null;
  }

  function signerDetailLine(label, value, extraValueClass) {
    return [
      "<div class='signer-detail-line'>",
      "<span class='signer-detail-label'>" + escapeHtml(label) + ":</span> ",
      "<span class='signer-detail-value" + (extraValueClass || "") + "'>" + escapeHtml(value) + "</span>",
      "</div>",
    ].join("");
  }

  function tile(label, value) {
    return [
      "<div class='timing-tile'>",
      "<span class='panel-kicker'>" + escapeHtml(label) + "</span>",
      "<strong>" + formatDuration(value) + "</strong>",
      "</div>",
    ].join("");
  }

  function formatDuration(value) {
    if (value === null || value === undefined || value === 0) {
      return "0 ms";
    }
    const ms = Number(value);
    if (ms >= 1000) {
      return (ms / 1000).toFixed(2) + " s";
    }
    return Math.round(ms) + " ms";
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function clamp(value, min, max) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return min;
    return Math.max(min, Math.min(max, parsed));
  }

  function setStatus(message) {
    elements.statusText.textContent = message;
  }

  function handleError(error) {
    const message = error && error.message ? error.message : String(error);
    elements.statusText.textContent = message;
    console.error(error);
  }

  async function apiGet(pathname) {
    const response = await fetch(pathname);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Request failed.");
    }
    return payload;
  }

  async function apiPost(pathname, body) {
    const response = await fetch(pathname, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Request failed.");
    }
    return payload;
  }

  async function downloadFile(pathname, filename) {
    const response = await fetch(pathname);
    if (!response.ok) {
      let message = "Download failed.";
      try {
        const payload = await response.json();
        message = payload.error || message;
      } catch (error) {
        message = response.statusText || message;
      }
      throw new Error(message);
    }

    const blob = await response.blob();
    const objectUrl = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename || "proof_bundle.zip";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.URL.revokeObjectURL(objectUrl);
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function escapeAttr(value) {
    return escapeHtml(value);
  }
})();

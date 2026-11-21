# 🛡️ VouchWeb

**TLS/HTTPS for the Open Agentic Web — Zero-Server Cryptographic Handshakes & Sandboxed Execution for Browser Agents.**

Built for the **Open Agentic Web Challenge** (Cognizant AI Lab, MIT Media Lab NANDA, Mozilla Otari, and AWS).

---

## 🌐 Overview

Today's Open Agentic Web operates much like the early 1995 web before SSL/TLS: when a browser-based agent discovers an external agentic website via its `.json` manifest and delegates a task, it has no server-free way to verify that the manifest wasn't tampered with or guarantee that the remote agent isn't injecting hidden prompts to exfiltrate local keys.

**VouchWeb** solves Agent-to-Agent (A2A) trust and execution isolation **100% client-side in the browser**:
1. **Cryptographic Manifest Attestation (`WebCrypto`):** Generates ECDSA P-256 keypairs, signs `agent.json` capability manifests, and cryptographically verifies remote agent identities via `window.crypto.subtle` with zero backend servers.
2. **Ephemeral Web Worker Airgap:** Isolates untrusted cross-origin agent responses inside a locked-down `Blob` Web Worker (`fetch`, `XMLHttpRequest`, and `importScripts` disabled) to strip hidden prompt injections, unauthorized exfiltration URLs, and schema violations before returning sanitized JSON.
3. **Proof-of-Capability Dry-Run Probes:** Executes lightweight synthetic micro-challenges against discovered agents to measure latency and schema adherence, computing a live `0–100` Trust Score.
4. **Cross-Origin Browser Mesh Runtime:** Exposes a zero-dependency ES module (`runtime.js`) and `window.postMessage` listener so any website on the Open Agentic Web can integrate VouchWeb in three lines of code.

---

## 📂 Open Agentic Web Conformance

This repository exposes all required Open Agentic Web specification endpoints out of the box:

| Endpoint | Description |
| :--- | :--- |
| `/agent.json` & `/.well-known/agent.json` | Machine-readable capability manifest declaring VouchWeb's endpoints, supported verification primitives, and public key metadata. |
| `/runtime.js` | Standalone, zero-dependency ES Module browser runtime (`export class VouchWebRuntime`). |
| `/` | Interactive Security Control Plane (Live Trust Arena, Manifest Signer & Auditor, Live Spec Inspector, and Zero-Key / BYOK LLM Config). |

---

## ⚡ Quick Start (Drop-In Integration)

Any Open Agentic Web site can verify and sandbox external agent payloads using VouchWeb's public runtime:

```html
<script type="module">
  import { VouchWebRuntime } from '[https://your-site.vercel.app/runtime.js](https://your-site.vercel.app/runtime.js)';

  const vouch = new VouchWebRuntime();

  // 1. Discover & verify an external agent's manifest
  const manifest = await vouch.discoverAgent('[https://external-agent-site.example](https://external-agent-site.example)');

  // 2. Inspect & sanitize an untrusted agent payload inside an isolated Web Worker airgap
  const result = await vouch.inspectPayload(untrustedAgentResponse);
  console.log('Sanitized Output:', result.sanitized, 'Threats Blocked:', result.threats);
</script>

# 1. Clone the repository
git clone https://github.com/darrenthanawinn-ux/vouchweb.git
cd vouchweb

# 2. Install dependencies
npm install

# 3. Start the local development server
npm run dev

vouchweb/
├── public/
│   ├── .well-known/
│   │   └── agent.json      # Open Agentic Web discovery manifest
│   ├── agent.json          # Root capability manifest
│   └── runtime.js          # Zero-dependency WebCrypto + Web Worker sandbox runtime
├── src/
│   ├── App.tsx             # Interactive Security Control Plane (4-tab UI)
│   └── main.tsx            # React entry point
├── vercel.json             # CORS headers (Access-Control-Allow-Origin: *) for cross-site agents
├── index.html
├── package.json
└── vite.config.ts

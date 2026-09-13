<!-- mcp-name: io.github.CSOAI-ORG/gdpr-compliance-ai-mcp -->

> Verification is free and public: signed measurement cards and live verification at **https://councilof.ai** — measurement, not certification.

[![MCP Scorecard: 86/100](https://img.shields.io/badge/proofof.ai-86%2F100-5b21b6)](https://proofof.ai/scorecard/gdpr-compliance-ai-mcp.html)

# Gdpr Compliance Ai MCP


[![Council of AI](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://councilof.ai)
[![PAYG enabled](https://img.shields.io/badge/PAYG-%C2%A30.05%2Fcall-7c3aed?logo=stripe&logoColor=white&labelColor=1a1a2e)](https://councilof.ai/payg)
[![GSPC](https://img.shields.io/badge/GSPC-UNMEASURED-9ca3af)](https://councilof.ai/api/gspc)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/gdpr_compliance_ai_mcp/)

> GDPR compliance MCP — DPIA automation, Article 30 records, Article 22 automated decision-making a...

GDPR compliance MCP — DPIA automation, Article 30 records, Article 22 automated decision-making audit, data subject request workflow.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install gdpr_compliance_ai_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install gdpr-compliance-ai-mcp --client claude
```

## ⚡ Pay-per-call (PAYG) — no subscription

This MCP supports universal pay-per-call billing across the MEOK compliance fleet:

```bash
# One-time setup
export MEOK_PAYG_KEY="your_topup_token"

# Every tool call now deducts £0.05 from your balance.
# When balance hits zero, the tool returns a top-up URL.
# Works across all 7 MEOK compliance MCPs with the same token.
```

- **No subscription** — top up once, deduct per call.
- **£0.05/call default** (configurable via `MEOK_PAYG_RATE_GBP`).
- **USDC on Base L2 accepted** — set `MEOK_X402_RECEIVER` and pay via stablecoin.
- **Backward-compatible** — when `MEOK_PAYG_KEY` is unset, behaviour is unchanged.

**Get a token**: [councilof.ai/payg](https://councilof.ai/payg) (£10 / £50 / £200 top-up tiers).


## ✨ Features

- GDPR Chapter V compliance
- Cross-region data guard
- Data localization
- Transfer mechanism validation
- Breach detection

## 📖 Documentation

- [Full Documentation](https://docs.councilof.ai/gdpr-compliance-ai-mcp)
- [API Reference](https://councilof.ai/api-docs)
- [EU AI Act Compliance Guide](https://councilof.ai)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](mailto:nicholas@councilof.ai?subject=Compliance%20diagnostic)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?


[View Pricing →](https://councilof.ai/payg) | [Contact Sales →](mailto:sales@councilof.ai)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[Council of AI](https://councilof.ai)** ecosystem — 26 PyPI packages · ~public measurement tools.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [councilof.ai](https://councilof.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://councilof.ai">Council of AI</a> · UK Companies House 16939677</sub>
</p>


## Configuration

Add to your `claude_desktop_config.json` (Claude Desktop) or your MCP client config:

```json
{
  "mcpServers": {
    "gdpr-compliance-ai-mcp": {
      "command": "uvx",
      "args": ["gdpr-compliance-ai-mcp"]
    }
  }
}
```

Or: `pip install gdpr-compliance-ai-mcp` then run the `gdpr-compliance-ai-mcp` command (stdio transport).

## Examples

Once configured, ask your assistant, for example:
- "Use `classify_processing` to …"
- "Use `lawful_basis_assessment` to …"
- "Use `dpia_generator` to …"

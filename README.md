# GDPR Compliance for AI Systems MCP Server

> **By [MEOK AI Labs](https://meok.ai)** -- Sovereign AI tools for everyone.

Full GDPR compliance assessment for AI/ML systems. Classify processing activities, determine lawful basis (6 bases under Article 6), generate DPIAs (Article 35), handle data subject rights (Articles 15-22), assess breach notification (72-hour rule), and crosswalk to EU AI Act.

Part of the **CSOAI Governance Suite**: GDPR + EU AI Act + ISO 42001 + ISO 27001 + SOC 2.

[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `classify_processing` | Classify data processing activities per GDPR articles |
| `lawful_basis_assessment` | Determine lawful basis (6 bases under Article 6) |
| `dpia_generator` | Generate Data Protection Impact Assessment (Article 35) |
| `rights_request_handler` | Handle data subject rights (Articles 15-22) |
| `breach_notification` | Assess breach severity and 72-hour notification requirements |
| `crosswalk_to_eu_ai_act` | Map GDPR requirements to EU AI Act obligations |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/gdpr-compliance-ai-mcp.git
cd gdpr-compliance-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "gdpr-compliance-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/gdpr-compliance-ai-mcp"
    }
  }
}
```

## Coverage

- **6 Lawful Bases** (Article 6) with AI-specific assessment
- **8 Data Subject Rights** (Articles 15-22) with response guidance
- **DPIA Generation** per Article 35 with risk scoring
- **72-Hour Breach Notification** assessment (Articles 33-34)
- **9 GDPR-to-EU AI Act crosswalk mappings** including the Article 9/10(5) tension
- **AI-specific considerations** throughout (training data, model memorization, automated decisions)

## The Crosswalk Advantage

The `crosswalk_to_eu_ai_act` tool shows exactly where GDPR compliance satisfies EU AI Act requirements and where tension exists -- particularly the Article 9 special categories vs Article 10(5) bias monitoring pathway.

## License

MIT -- see [LICENSE](LICENSE)

---

## 🏢 Enterprise & Pro Licensing

| Plan | Price | Link |
|------|-------|------|
| **Compliance Trinity** (EU AI Act + GDPR + ISO 42001) | £79/mo | [Subscribe](https://buy.stripe.com/eVq5kF2G0aEG3812Yg8k82i) |
| **Full Suite** (9 MCPs) | £999/mo | [Subscribe](https://buy.stripe.com/6oU14p0xS4giaAtbuM8k82q) |
| **Enterprise Assessment** | £5,000 | [Book Now](https://buy.stripe.com/00waEZ6Wg8wy7oh0Q88k82k) |

> Part of [CSOAI](https://csoai.org) compliance ecosystem — 208+ MCP servers.

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | [csoai.org](https://csoai.org) | nicholas@meok.ai

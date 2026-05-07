<div align="center">

[![PyPI](https://img.shields.io/pypi/v/gdpr-compliance-ai-mcp)](https://pypi.org/project/gdpr-compliance-ai-mcp/)
[![Downloads](https://img.shields.io/pypi/dm/gdpr-compliance-ai-mcp)](https://pypi.org/project/gdpr-compliance-ai-mcp/)
[![GitHub stars](https://img.shields.io/github/stars/CSOAI-ORG/gdpr-compliance-ai-mcp)](https://github.com/CSOAI-ORG/gdpr-compliance-ai-mcp/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

# GDPR Compliance MCP

**Full GDPR compliance assessment for AI/ML systems.**

Lawful basis (Article 6) · DPIAs (Article 35) · Data subject rights (Articles 15-22) · Breach notification (72h rule) · EU AI Act crosswalk

Penalties: up to 4% of global turnover or EUR 20M.

[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-224+_servers-purple)](https://meok.ai)

[Install](#install) · [Tools](#tools) · [Pricing](#pricing)

</div>

---

## Why This Exists

Every AI system processing personal data needs GDPR compliance. Article 35 requires a DPIA for high-risk processing — which includes most ML training on personal data. Article 22 restricts automated decision-making. The 72-hour breach notification window leaves no room for manual processes.

This MCP automates the GDPR assessment: classify processing activities, determine lawful basis, generate DPIAs, check data subject rights workflows, and crosswalk findings to EU AI Act obligations.

## Install

```bash
pip install gdpr-compliance-ai-mcp
```

## Tools

| Tool | GDPR Article | What it does |
|------|-------------|-------------|
| `classify_processing` | Art 4, 6 | Processing activity classification + lawful basis |
| `generate_dpia` | Art 35 | Data Protection Impact Assessment generator |
| `check_data_rights` | Art 15-22 | Data subject rights workflow audit |
| `assess_breach_process` | Art 33-34 | 72-hour breach notification readiness |
| `check_automated_decisions` | Art 22 | Automated decision-making compliance |
| `crosswalk_eu_ai_act` | — | GDPR-to-EU AI Act obligation mapping |
| `run_full_audit` | All | Complete GDPR readiness assessment |
| `sign_attestation` | — | HMAC-SHA256 signed compliance certificate |

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | £0 | 10 calls/day |
| **Pro** | £199/mo | Unlimited + HMAC-signed attestations |
| **Enterprise** | £1,499/mo | Multi-tenant + co-branded reports |

[Subscribe to Pro](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836) · [Enterprise](https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837)

## Attestation API

```
POST https://meok-attestation-api.vercel.app/sign
GET  https://meok-attestation-api.vercel.app/verify/{cert_id}
```

## Links

- Website: [meok.ai](https://meok.ai)
- All MCP servers: [meok.ai/labs/mcp/servers](https://meok.ai/labs/mcp/servers)
- Enterprise support: nicholas@csoai.org

## License

MIT

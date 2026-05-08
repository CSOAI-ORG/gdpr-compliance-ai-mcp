<div align="center">

# Gdpr Compliance Ai MCP

**MCP server for gdpr compliance ai mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-gdpr-compliance-ai-mcp)](https://pypi.org/project/meok-gdpr-compliance-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Gdpr Compliance Ai MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `classify_processing` | Classify data processing activities per GDPR articles. Determines which |
| `lawful_basis_assessment` | Determine the appropriate lawful basis for processing under GDPR Article 6. |
| `dpia_generator` | Generate a Data Protection Impact Assessment per GDPR Article 35. |
| `rights_request_handler` | Handle data subject rights requests under GDPR Articles 15-22. |
| `breach_notification` | Assess breach severity and notification requirements under GDPR Articles |
| `crosswalk_to_eu_ai_act` | Map GDPR requirements to EU AI Act obligations. Shows where GDPR |

## Installation

```bash
pip install meok-gdpr-compliance-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "gdpr-compliance-ai-mcp": {
      "command": "python",
      "args": ["-m", "meok_gdpr_compliance_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 6 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)

# ZeroTrace API Documentation (v1.0.3)

**Enterprise Multi-Tenant Edition**

---

## Overview

The ZeroTrace API provides a secure, speculative interface for agentic operations. All requests are routed through the **TenantRouter** to isolated **Security Cells** based on the provided Organization ID.

## Base URL
`https://api.zerotrace.ai/v1`

---

## Endpoints

### 1. Execute Agent Action
`POST /execute`

The primary entry point. "Races" the security mesh against the LLM inference.

**Headers**
| Header | Type | Description |
| :--- | :--- | :--- |
| `Authorization` | Bearer | API Key for the cell. |
| `X-Organization-ID` | UUID | **Required**. Identifies the Neo4j Shard / Security Cell. |
| `X-NHI-Token` | JWT | **Required**. Identity token for the specific Non-Human Identity (Agent). |
| `X-Passkey-Signature` | String | Optional. WebAuthn signature for high-privilege actions (Tier 3). |

**Request Body**
```json
{
  "prompt": "Analyze the merger agreement for flight risks.",
  "context_id": "session_9924_x",
  "tier_preference": "shielded",
  "tools_available": [
    {
      "name": "pdf_parser",
      "description": "Extracts text from PDF documents."
    },
    {
      "name": "email_sender",
      "description": "Sends emails to internal domains."
    }
  ]
}
```

**Response (200 OK)**
```json
{
  "status": "allowed",
  "latency_ms": 38,
  "usage": {
    "tier": "Tier 2 (Shielded)",
    "cost_usd": 0.004
  },
  "content": "Analysis complete. The merger agreement contains..."
}
```

**Response (403 Forbidden - Blocked)**
```json
{
  "status": "blocked",
  "latency_ms": 42,
  "vector_id": "V39",
  "reason": "Toxic Combination: pdf_parser + email_sender detected in sensitive context.",
  "incident_id": "case_8821_af"
}
```

---

## Error Handling

| Code | Meaning | Action |
| :--- | :--- | :--- |
| `401` | Unauthorized | Check API Key and `X-NHI-Token`. |
| `403` | Blocked / Forbidden | Security Vector triggered. Review `incident_id`. |
| `404` | Tenant Not Found | Invalid `X-Organization-ID`. Check onboarding status. |
| `429` | Rate Limited | Cell capacity exceeded. Retry with exponential backoff. |

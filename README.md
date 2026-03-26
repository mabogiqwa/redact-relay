# Ikhaka AI — Privacy Redaction API

A self-hosted API that strips personal information out of prompts before they reach an LLM, then puts it back into the response so the output still reads naturally. No real names, ID numbers, or contact details ever leave your infrastructure.

Built with South African law in mind — specifically POPIA Section 72, which treats sending personal information to an offshore LLM provider as a cross-border data transfer.

---

## How it works

The flow is straightforward:

1. You send a prompt to `/redact`
2. The API finds all PII and replaces it with typed placeholders like `[PERSON_1]` and `[SA_ID_1]`
3. You send the cleaned prompt to whatever LLM you are using
4. You send the LLM response to `/restore` with the same session ID
5. The API swaps the placeholders back out for the real values

The LLM sees anonymised text. Your users see a response with real names and numbers, as if nothing happened.

---

## What it detects

**Structured identifiers (regex-based)**
- SA ID numbers — with Luhn checksum validation
- Passports and SA company registration numbers
- Phone numbers (mobile and landline, local and international format)
- Email addresses
- Bank account numbers
- SA tax reference numbers
- Dates
- SA street addresses and postcodes
- URLs

**Healthcare**
- Medical record numbers (MRN format)
- HPCSA practitioner registration numbers
- Healthcare institution names

**Insurance and legal**
- Insurance policy numbers
- Police and court case numbers
- Vehicle identification numbers (VIN)
- Employee reference numbers

**Names and organisations (NER-based)**
- Person names, including Afrikaans particles like "van der" and "du"
- Organisation names
- Location names (off by default — city names are rarely PII on their own)

When spaCy is not installed, the engine falls back to a capitalisation-based heuristic that handles honorifics, hyphenated names, and compound surnames reasonably well.

---

## Domain modes

You can tune which entity types get redacted by setting the mode on the `PromptRedactor`:

| Mode | What changes |
|------|-------------|
| `general` | Names, IDs, contacts. Locations and vehicles off. |
| `medical` | Adds hospital names, MRNs, HPCSA numbers, and locations. |
| `insurance` | Adds VINs and locations. Organisation names off. |
| `legal` | Adds locations and organisation names. |
| `financial` | Adds organisation names (employer and bank names treated as PII). |

---

## Quick start

Run locally with Docker:

```bash
docker build -t ikhaka-api .
docker run -p 8080:8080 -e IKHAKA_MASTER_KEY=your-secret ikhaka-api
```

Or with uvicorn directly:

```bash
pip install -r requirements.txt
uvicorn api_server:app --reload --port 8080
```

A demo API key is printed to the console on startup. Use it to try things out immediately at `http://localhost:8080/docs`.

---

## Authentication

Every request requires an API key in the `X-API-Key` header.

```bash
curl -X POST http://localhost:8080/redact \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "Please review the account for Kevin Naidoo, ID 8009125011085."}'
```

To create new keys, call `POST /admin/keys` with the `X-Admin-Key` header set to your master key.

---

## Core endpoints

### POST /redact

Takes a text prompt and returns the redacted version.

Request:
```json
{
  "text": "Draft a letter for Sipho Nkosi (ID: 9001010009081, +27 82 123 4567).",
  "session_id": null
}
```

Response:
```json
{
  "redacted": "Draft a letter for [PERSON_1] (ID: [SA_ID_1], [PHONE_1]).",
  "session_id": "a1b2c3d4-...",
  "entities": { "PERSON": 1, "SA_ID": 1, "PHONE": 1 },
  "total_entities": 3,
  "placeholders": {
    "[PERSON_1]": "Sipho Nkosi",
    "[SA_ID_1]": "9001010009081",
    "[PHONE_1]": "+27 82 123 4567"
  },
  "latency_ms": 4.2
}
```

Pass `session_id` on follow-up turns in a conversation to keep placeholder numbering consistent — `[PERSON_1]` will always refer to the same person across the whole session.

---

### POST /restore

Takes an LLM response and the session ID, and puts the real values back.

Request:
```json
{
  "text": "I have reviewed [PERSON_1]'s account. [SA_ID_1] appears valid.",
  "session_id": "a1b2c3d4-..."
}
```

Response:
```json
{
  "restored": "I have reviewed Sipho Nkosi's account. 9001010009081 appears valid.",
  "session_id": "a1b2c3d4-...",
  "unreplaced_placeholders": []
}
```

The `unreplaced_placeholders` field will list any tokens the LLM invented that had no matching entry in the session vault.

---

### POST /redact/messages

For multi-turn chat, you can pass a full OpenAI-style messages list and have all turns redacted in one call.

```json
{
  "messages": [
    { "role": "system", "content": "You are a helpful assistant." },
    { "role": "user", "content": "Summarise the case for Lerato Kgomo, ID 8907190044085." }
  ]
}
```

The response follows the same shape as `/redact`, with `redacted` containing the JSON-encoded messages list.

---

### DELETE /sessions/{session_id}

Clears the in-memory vault for a session. Call this when a conversation ends. Under POPIA's data minimisation principle, you should not hold personal information in memory any longer than necessary.

---

### GET /usage

Returns your call counts, entity totals, and remaining daily quota for today.

---

### GET /audit

Returns a POPIA-aligned processing summary for your tenant, confirming that no personal information is persisted to disk or logs, and that the vault is cleared on session close.

---

## Tiers

| Tier | Daily calls | Rate limit | Price |
|------|-------------|------------|-------|
| Starter | 1,000 | 10 req/min | Free |
| Pro | 50,000 | 120 req/min | $99/mo |
| Enterprise | Unlimited | 600 req/min | Contact us |

Limits reset at midnight UTC. The API returns a `429` with a `retry_after_seconds` field when a limit is hit.

---

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `IKHAKA_MASTER_KEY` | Protects the `/admin/keys` endpoint | `dev-master-key-change-in-prod` |
| `IKHAKA_REDIS_URL` | Enables Redis-backed rate limiting and session persistence | In-memory |
| `IKHAKA_ENV` | `production`, `staging`, or `development` | `development` |
| `SPACY_MODEL` | spaCy model name to load, e.g. `en_core_web_sm` | Auto-detect |

In production, always set `IKHAKA_MASTER_KEY` to a strong random value. The in-memory key store is suitable for single-instance deployments; connect Redis for multi-worker or horizontally scaled setups.

---

## Using the engine directly

If you want to use the redaction logic without the API layer:

```python
from differential_engine import PromptRedactor

redactor = PromptRedactor()

result = redactor.redact("Please review Sipho Nkosi's claim, ID 9001010009081")
print(result.redacted)
# → "Please review [PERSON_1]'s claim, ID [SA_ID_1]"

# Send result.redacted to your LLM, then:
restored = redactor.restore(llm_response, result.session_id)
```

For multi-turn conversations, pass a `RedactionSession` object across calls so placeholder numbering stays consistent across turns.

---

## POPIA notes

The key legal basis this addresses is POPIA Section 72: sending personal information to an offshore service constitutes a cross-border transfer and requires specific conditions to be met. By redacting before transmission, identifiable personal information never leaves your infrastructure — the LLM receives only anonymised text.

The `/audit` endpoint provides a processing record confirming that original values are held in-memory only, for the duration of the session, and are never written to logs or disk.

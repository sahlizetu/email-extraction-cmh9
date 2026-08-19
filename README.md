# Email Extraction #CMH9

A working Gmail IMAP extractor with six distinct output modes, MIME-aware text extraction, safe per-header transformations, live percentage progress, copy, and combined TXT export.

## Requirements

- Node.js 20+
- A Gmail account with 2-Step Verification enabled
- A Google App Password (never use your normal Gmail password)

## Run locally

```bash
npm install
npm test
npm start
```

Open `http://localhost:3000`.

## Gmail setup

1. Enable 2-Step Verification in your Google Account.
2. Create an App Password for “Mail”.
3. Enter the Gmail address and 16-character App Password in the connection card.

Credentials are never logged or written to disk. When “Keep me connected” is enabled, the Gmail address and App Password are protected with AES-256-GCM inside a Secure, HTTP-only, SameSite cookie for 30 days. Set a strong `SESSION_SECRET` in Railway so the encrypted login survives server restarts. Logging out destroys the cookie.

## Extraction behavior

- **Clean Headers:** transforms applicable headers and preserves the raw MIME body.
- **Text Only:** returns the parsed readable plain-text body; HTML is converted only when no text part is available.
- **Newsletter Original:** returns the byte-identical raw source as `.eml`; all transformations are bypassed.
- **Headers Only:** returns cleaned headers with no body using dedicated From Name, Language Code, Return Path, Subject, and Boundary parameters. Add Sender is optional and off by default.
- **Body Only:** returns the raw body bytes after the RFC header separator, with no message headers.
- **Received Only:** returns all `Received` fields in their original order, including folded continuation lines.

Extraction runs as a background job and the browser polls lightweight progress updates, showing a real percentage and processed-email count. Download always streams one `.txt` file containing every extracted email with `__SEP__` between messages. Start and Limit use IMAP sequence positions and are validated server-side. The default maximum extraction is 100 messages per request; configure `MAX_EXTRACTION_LIMIT` if needed.

## Security and deployment

- HTTPS is required in production.
- Set `SESSION_SECRET` to at least 32 random characters. Example: `openssl rand -hex 32`.
- The app uses secure headers, strict same-site HTTP-only session cookies, input limits, endpoint rate limits, short session expiry, and generic server errors.
- Deploy as a persistent Node service or Docker container. A long-lived server is recommended because credentials and extraction results intentionally remain in memory.
- Do not deploy App Passwords in environment variables and do not commit `.env` files.

### Docker

```bash
docker build -t email-extraction-cmh9 .
docker run --rm -p 3000:3000 email-extraction-cmh9
```

## Test coverage

The included Node test suite verifies Date, To, Message-ID, From `[ID]`, Subject `[ID]`, domain replacement, all Received fields, Reply-To removal/preservation, duplicate-Cc prevention, the combined screenshot configuration, original-source fidelity, and mode separation.

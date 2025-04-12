# ChainGuardian Token Orchestrator

**ChainGuardian** is a decentralized protocol written in Clarity for managing token envelopes—temporary, conditional commitments of STX token transfers. It supports time-based delivery logic, secure reversion paths, and multi-signature authorization for high-value operations.

## 🚀 Features

- **Token Envelopes**: Create envelopes that define token transfer conditions (origin, destination, amount, expiry).
- **Conditional Delivery**: Execute or revert envelopes based on on-chain conditions and governance roles.
- **Envelope Termination**: Allows the originator to cancel the envelope within the defined window.
- **Multi-Signature Verification**: Enforces multi-party approval for sensitive, high-value operations.
- **Time-Limited Transactions**: Built-in envelope expiration and customizable extensions.

## 🛠️ Contract Overview

- `EnvelopeRegistry`: Stores all token transfer envelopes.
- `execute-delivery`: Transfers tokens to the recipient if conditions are met.
- `revert-delivery`: Returns tokens to the sender if not executed.
- `terminate-envelope`: Allows originator to cancel the envelope.
- `modify-envelope-timeframe`: Extend the envelope's expiration.
- `verify-multi-signature`: Verifies multi-party authorization on high-value transactions.

## 🧱 Constants

- `PROTOCOL_GOVERNOR`: Contract administrator with override permissions.
- `ENVELOPE_DURATION_BLOCKS`: Default envelope lifetime (~7 days).
- Multiple error codes for granular failure handling.

## 🧪 Usage

Deploy the contract to the Stacks blockchain using the Clarity CLI or within a testnet/sandbox environment. Interact via:
- Clarinet Console
- Stacks.js
- Any Clarity-compatible frontend

## 📜 Example Workflow

1. **Create Envelope** (future implementation)
2. **Execute Delivery**
3. **Revert or Terminate if needed**
4. **Optional**: Extend time or require multi-sig for final approval

## 🧾 License

MIT License

---

> Built for programmable custody, secure delivery, and decentralized governance.  
> **ChainGuardian** — Safeguarding token transitions with protocol precision.

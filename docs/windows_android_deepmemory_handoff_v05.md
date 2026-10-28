# STM v0.5 source candidate: Windows, Android/Linux and 30-day review

Date: 2026-10-28. **Not installed, enabled, or connected to Vera's private
conversation interface.** This document records a proposed host integration,
not a deployed data-retention policy.

## Patrick's requested direction and the unresolved policy choice

- Intended platforms: **Windows** and **Android (Linux kernel)**. The present
  VeraOS source also describes a Linux Buildroot guest. These are distinct
  trust boundaries and do not share a verified logged-in user automatically.
- Proposed timeline: a conversation may become **eligible for a supervised
  DeepMemoryStorage review after 30 days**. This is not permission to make a
  permanent copy, nor a verified archive expiration duration. Consent to
  retain in short-term storage is **not** consent to export elsewhere.
- The application must separately establish (1) maximum source retention;
  (2) when review starts, early enough to avoid source expiry; (3) whether
  content may be exported at all, and which privacy labels; (4) destination
  access control and retention/deletion/correction semantics; and (5) the
  behavior if review or transfer fails. Existing source deadlines remain in
  force unless the host obtains new explicit authority to change them.

## Distinct trust and lifecycle states

1. **Working context:** bounded STM session with short TTL, ephemeral state.
2. **Opt-in local conversation evidence:** consent-gated SQLite archive with
   per-record deadline, current authentication and scope authorization.
3. **Eligible for review:** age/scope/provenance/consent check; it authorizes
   **no effect** by itself and cannot bypass an expired source record.
4. **Authorized export candidate:** fresh, separate affirmative long-term
   storage consent, authenticated host signer, exact target, bounded policy,
   correction/delete propagation plan and privacy-scope check.
5. **Accepted by private destination:** verified receipt bound to exact source
   id/version/content digest, destination scope and policy. A callback
   returning `True` is not a durable receipt.
6. **Source retirement:** a separately authorized and verified step after
   source policy requirements are met. Export must never disable ordinary
   expiration or silently keep data indefinitely during retry.

No automatic move, deletion, episodic admission, semantic belief, identity
update or model training is authorized by states (3) or (4).

## Destination risk: current DeepMemoryStorage source

The canonical `thebrazenbeard/deepmemorystorage` repository was verified
**public** on this date. Its documented current mechanism is an append-only
historical-evidence ledger and query/catalog tools. There is **no verified
general-purpose private ingestion endpoint**. Its source is marked
source-available proprietary, not an interchangeable licensed software
dependency. **Never publish private conversations to that GitHub repository.**

An optional host-supplied transfer sink must be deliberately configured,
authenticated, private, auditable and independently qualified to satisfy
future correction/deletion/consent revocation; otherwise export fails closed.
Repository append-only provenance does not guarantee private erasure.

## Platform identity

| Environment | Possible trust primitive | What remains unproven |
| --- | --- | --- |
| Windows desktop | Named pipe with explicit restrictive ACL, server-side client token/SID identification | Real VeraOS user/session mapping, secure pipe creation/impersonation and native Windows tests |
| Android on Linux | Kernel `AF_UNIX` peer UID for same-device, same-kernel peers; Android Binder calling UID only within a verified Binder transaction | Package signature/UID-to-principal mapping, APK transport binding and actual Android device tests |
| VeraOS Buildroot guest | Linux peer authentication in guest (if deployed) | Trust propagation from host Windows/Android into guest; actual conversation runtime wiring |
| Cross-device | Separately paired, mutually authenticated host protocol | No such transport, credential issuer or revocation lifecycle has been implemented here |

Browser `Origin`, HTTP `Host`, `localhost`, a user-supplied UID/SID,
`conversation_id`, or Android package name alone are **not** authentication.
The current VeraOS `/api/conversation` and `/api/conversation/history` loopback
handlers remain ineligible for private STM history access until a real host
authenticator replaces their identity gap.

## Minimum qualification before any private data

- Reconcile user-granted numeric source TTL and 30-day review boundary, with
  explicit destination-specific consent and retention/deletion semantics.
- Verify the authenticated Windows and Android entry points on the *actual*
  devices, including local attacker, impersonation, replay and revocation tests.
- Run a supervised host scheduler with restart recovery and zero-unregistered-
  scope audit, without bypassing expiry while waiting for export.
- Inventory and enforce deletion on original Vera journals, STM SQLite/FTS/WAL,
  caches, checkpoints, backups and any privately operated DMS destination.
- Use only synthetic transcripts for first system tests; require separate
  authorization for live installation and activation.

Primary platform references: [Microsoft named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[named-pipe client impersonation](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client),
[Android Binder identity](https://developer.android.com/reference/android/os/Binder),
and [Linux `SO_PEERCRED`](https://man7.org/linux/man-pages/man7/unix.7.html).

# Security policy

This project is experimental and has no production support commitment. It
handles device identifiers, client certificates, push tokens, enrollment
challenges, configuration profiles, and private keys, so report security
issues privately.

## Report privately

Use the repository’s [private security advisory
form](https://github.com/quantum-box/mdm/security/advisories/new). Do not open a
public issue for an undisclosed vulnerability. If the form is unavailable,
contact the repository maintainers through the private channel associated with
the project and include “security report” in the subject.

Include:

- the affected commit or version;
- a short impact statement;
- a minimal reproduction that does not contain live credentials or real device
  identifiers;
- logs with UDIDs, push tokens, client certificates, enrollment challenges,
  private keys, and profile payloads redacted.

Do not test against another person’s device, Apple account, APNs identity, or
production service. Stop a test that could send commands outside the isolated
device set.

## Credential exposure

If a management token, SCEP CA key, APNs identity, HTTPS key, or device
certificate is exposed, revoke or rotate it immediately and record the event in
the audit trail. A database backup can contain enrollment and command metadata;
keep it encrypted and access-controlled.

## Scope

The initial implementation supports a device-channel subset. User-channel
messages and Declarative Device Management are outside the current support
boundary. A report that crosses those boundaries is still useful, but include
the exact input and expected behavior so it can be classified correctly.

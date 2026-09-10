# Security Guidance

Password validation is part of an authentication/security boundary. The library should therefore be integrated with care.

## Never log plaintext passwords

Do not write passwords to:

- application logs;
- debug logs;
- audit events;
- exception messages;
- HTTP access logs;
- traces;
- metrics labels;
- analytics events;
- crash reports.

For example, avoid:

```python
logger.info("Password validation failed: %s", password)
```

Log only non-sensitive rule identifiers or high-level outcomes.

## Do not use this package as password storage

The package validates and analyzes passwords. It does not replace password hashing/storage.

A production application should hash passwords with a password-hashing mechanism appropriate to the application and store only the resulting password verifier.

## Avoid password persistence in custom rules

Custom rules should not retain password values in instance state, caches, class variables, or telemetry.

Bad pattern:

```python
self.last_password = password
```

Good pattern:

```python
return self._failed(
    message="Password contains a prohibited value",
    code="PROHIBITED_VALUE",
)
```

## Be careful with dictionary analysis

Dictionary and common-password checks can improve password-risk detection, but the data source itself should be treated as application data. Keep resource files controlled and review their provenance.

If external files are configured, validate their paths and permissions according to your deployment model.

## Do not expose unnecessary detail

For public-facing authentication APIs, consider whether returning every failed rule reveals too much information. The library provides detailed structured results because applications may need them, but the API boundary should decide what information is safe to disclose.

## Rate limiting and authentication controls

Password validation does not protect an authentication endpoint by itself. Applications should separately consider:

- login rate limiting;
- account lockout or adaptive controls where appropriate;
- MFA;
- credential stuffing defenses;
- secure session management;
- transport security;
- password-reset security.

## Strength scoring is heuristic

The estimated entropy and pattern scoring in this project are heuristic measurements. They should not be interpreted as cryptographic guarantees.

If a security requirement depends on a specific assurance level, define and validate that requirement independently.

## Environment configuration

Do not commit production `.env` files containing secrets. Environment variables are configuration inputs, not a secure secret-management strategy by themselves.

For deployment secrets, use the secret-management facilities provided by your cloud/platform environment.

## Custom remote rules

A custom rule that calls an external service can create:

- latency;
- availability dependencies;
- retry complexity;
- data disclosure risks;
- denial-of-service amplification.

Avoid sending plaintext passwords to external systems unless the architecture and security requirements explicitly justify it.

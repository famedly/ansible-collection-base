# SSH hardening

This role is used for basic hardening of a SSH daemon. It features
common basic hardening features like disabling root login, requiring
pubkey authentication and disabling some unsafe-ish, rarely used features.

## Features

- `PasswordAuthentication no` which makes BF-attempts harder
- `ChallengeResponseAuthentication no` because we don't use it
- `PubkeyAuthentication yes` because only key-based auth is allowed
- `PermitRootLogin no` as it can pose a security threat
- `ClientAliveInterval 300` to disconnect all idle sessions after 300s=5m
- `Protocol 2` because SSHv1 has security issues and should not be used as fallback

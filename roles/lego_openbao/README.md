# lego for OpenBao ACME+EAB

- https://github.com/go-acme/lego
- https://openbao.org/api-docs/secret/pki/#acme-certificate-issuance

## Installation

This rolle assumes that a lego binary is already installed (use the `lego` role for that).
It sets up an ACME account for lego on an OpenBao instance using External Account Binding (EAB) and configures a separate systemd service to fetch certificates using that account.

## Usage

Set the following variables

- `lego_openbao_approle`: Approle credentials in the form `{"role_id": "some string", "secret_id": "some string"}` with permission to get new EAB tokens.
- `lego_openbao_issuer_hostname`: Hostname of the OpenBao instance.
- `lego_openbao_issuer_path` (default: `/v1/pki-int/roles/lego/acme`): Full path to the OpenBao role with ACME support.

The options regarding ACME challenges are the same as documented in the `lego` role, just prefixed with `lego_openbao_` instead of `lego_`.

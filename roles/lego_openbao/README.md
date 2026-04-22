# lego - Let's Encrypt client written in Go. 

Project Info: https://github.com/go-acme/lego

## Usage

### Installation

This rolle assumes that a lego binary is already installed (use the `lego` role for that).
It only sets up an ACME account for lego on an OpenBao instance and configures a separate systemd service to fetch certificates using that account.

### Request a certificate

#### Certificate

Pass `lego_certificate` to the role the data should look something like this:

```yml
lego_certificate:
  domains:
    - "example.domain"
    - "*.example.domain"
    - "another.example.domain"
  email: "admins@example.domain"
```

** Keep in mind that wildcard certificates (`*.example.domain`) can usually only be requested using a DNS challenge. **

#### Challenge

You can choose between `http`, `tls` and `dns` challenge types:

##### http (used by default)

```yml
lego_challenge:
  type: http
```

##### tls

```yml
lego_challenge:
  type: tls
```

##### DNS

When using a dns based challenge you have to supply your dns-provider (`cloudflare` for example). A list of supported providers can be found here [https://go-acme.github.io/lego/dns/](https://go-acme.github.io/lego/dns/).

```yml
lego_challenge:
  type: dns
  provider: my-dns-provider
```

Usually you have to pass additional configuration parameters to use a dns challenge, this is usually done using environment variables:

```yml
lego_configuration:
  environment:
    CLOUDFLARE_DNS_API_TOKEN: "supersecrettoken"
```

Which variables you need depends on your dns provider and is documented in the lego documentation.

## Additional configuration

### Environment variables and Parameters

You can customise all parameters and environment variables passed to lego during role execution and systemd execution using `lego_configuration`:

**Usually you don't have to change any `command_parameters`**

Lego has 4 (in normal operation only `run` and `renew` are used) commands, they share `global` parameters and each have their own additional parameters:
```yml
lego_configuration:
  command_parameters:
    global: 
      parameter: value
    run:
      parameter: value
    renew:
      parameter: value
  environment: 
    VARIABLE: VALUE
```
Parameters are automatically prefixed with `--` and passed to lego. Environment variables are treated as global options and passed every time.

Documentation on the parameters can be found here: [https://go-acme.github.io/lego/usage/cli/](https://go-acme.github.io/lego/usage/cli/)

**Keep in mind that the passed configuration will be merged with the generated / default configuration from above**

### Tasks

This role differentiates between 2 tasks:
- Playbook
  Is executed during the ansible run (only executed when the configuration changes or the initial installation ). It uses the `lego` command `run`: An acme-account is created and a certificate is requested.
- Systemd
  Is executed periodically by systemd, using the `renew` command: The validity of the certificate is checked, if it will expire soon (less than 30 days) a new certificate is requested.

### Hooks

You can request lego to run hooks after certain events. You can add those using `lego_configuration`. More info on hooks can be found here: [https://go-acme.github.io/lego/usage/cli/examples/#to-renew-the-certificate-and-hook](https://go-acme.github.io/lego/usage/cli/examples/) 

### Use an existing acme account
To use an existing acme account you have to pass its account uri and the private key like this:

**You MUST use a PEM-encoded private key:**
It must be wrapped with `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----`.
```yml
lego_acme_privkey: |
  -----BEGIN RSA PRIVATE KEY-----
  MYSUPERSECRETPRIVATEKEY
  MYSUPERSECRETPRIVATEKEY
  MYSUPERSECRETPRIVATEKEY
  -----END RSA PRIVATE KEY-----

lego_acme_account:
  registration:
    uri: "https://acme-v02.api.letsencrypt.org/acme/acct/my-account-id"
```

### Dependencies

This role assumes the `cryptography` python package is present on the system. It can be installed in different ways:

- set `lego_install_dependencies: true` which will attempt to install the `python3-cryptography` package on debian
- use the `famedly.base.pip` role:
```yaml
---

- name: Ensure lego is running
  hosts: [ lego ]
  become: yes
  roles:
    - role: famedly.base.pip
      vars:
        pip_packages:
          - name: cryptography
    - role: famedly.base.lego
      vars:
        lego_challenge:
          type: http
        lego_certificate:
          domains:
            - my.domain.tld
          email: acme@domain.tld
```

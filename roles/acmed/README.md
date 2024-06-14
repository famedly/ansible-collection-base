# famedly.base.acmed

a role for [`acmed`](https://github.com/beard-r/acmed) using our own [container image](https://github.com/famedly/container-image-acmed)

it provides 2 extra hooks configured by default: <br>
[`acmed-hook-rfc2136`](https://github.com/famedly/acmed-hook-rfc2136/) for dynamic dns updates <br>
[`acmed-hook-ssh`](https://github.com/famedly/acmed-hook-ssh/) for certificate distribution via ssh <br>


## Configuration
### Accounts

|key|default|required|
|-|-|-|
|`acmed_account_name`|*unset*|yes|
|`acmed_account_mailto`|*unset*|yes|
|`acmed_accounts`|derived from above| yes|
|`acmed_default_account`|`{{ acmed_accounts[0]['name'] }}`| no |

if you need more than a signle account you can define them like shown below.
``` yaml
acmed_accounts:
 - "{{ acmed_derived_account }}"
 - name: "meow awoo"
   contacts:
     - "meow@example.org"
```
---
### Endpoints

`acmed_endpoints` will include Let's Encrypt by default like shown below. <br>
`acmed_default_endpoint` will default to `"le_prod"`.

when using a different default provider, it is recommended to define it like shown below.

``` yaml
your_custom_provider:
  name: "your custom provider"
  url: "https://acme.example.org/directory"
  tos_agreed: true
  renew_delay: 8w
  random_early_renew: 1w

acmed_default_endpoint: "{{ your_custom_provider.name }}"
acmed_endpoints:
  - "{{ acmed_endpoint_le_prod }}"
  - "{{ acmed_endpoint_le_staging }}"
  - "{{ your_custom_endpoint }}"
```
---
### Hooks
this role comes with `acmed_hook_ssh` and `acmed_hook_rfc2136` by default.

the ssh hook is pretty simple to configure, it requires just one key <br>
```yaml
acmed_hook_ssh_user: "meow"
```

the dynamic dns updates hook is a bit more involved,
it requires all the keys shown in `your_zone` below.
```yaml
your_zone:
  name: "acme.example.org." # Don't forget the trailing dot!!!
  primary_ns: "ns0.example.org"
  tsig_name: "my-tsig-name"
  tsig_key: "" # base64 encoded key, standard alphabet, padded
  tsig_algorythm: "hmac-sha256"

acmed_hook_rfc2136_resolver: "1.1.1.1"
acmed_hook_rfc2136_zones:
 - "{{ your_zone }}"
```

### Certificate

call `tasks/configure_cert.yml` with the content in `acmed_certificate`

```yaml
acmed_certificate:
  # REQUIRED
  identifiers:
    - dns: "my_host.example.org"
      challenge: "dns-01"
    - dns: "some_service.example.org"
      challenge: "dns-01"

  # REQUIRED - with defaults
  account: "meow awoo"                    # `acmed_default_account`
  endpoint: "le_staging"                  # `acmed_default_endpoint`
  hooks: ["dns-01-rfc-2136", "ssh-send"]  # `acmed_default_hooks`

  # OPTIONAL - derived from endpoint or global
  random_early_renew: "1d"
  renew_delay: "4w"
  state: "present"

  # OPTIONAL
  env:
    HOOK_SSH_USER: "root"
  subject_attributes:
    country_name: DE
    organization_name: famedly
    organization_unit_name: infra
```

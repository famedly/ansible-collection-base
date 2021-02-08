# DNS management role

## Currently supported

- CloudFlare, via `community.general.cloudflare_dns` module. The cloudflare API token is passed in `dns_cloudflare_api_key`.

## Usage

You can pass in one or more zones in the `dns_zones` variable and set `dns_host_name_short` to your targets name.
All combinations of `dns_host_name_short`.`dns_zone` will be created as A/AAAA records,
if `dns_host_ipv4`/`dns_host_ipv6` were specified.

A `SSHFP` record can also be created for each zone, by adding an
entry of the form `{ algorithm: ECDSA, hash_type: SHA-256, fingerprint: $fingerprint }` to the
`dns_host_sshfp` array (multiple entries with different algorithms / hash_types are possible).

Additional host names can be specified in the `dns_host_names` array, with entries in the form
of `{ name: "mail", target: { ipv4: 0.0.0.0, ipv6: fe80::1 }, only: "myzone.tld" }`.
The `target.[ipv4|ipv6]` and `only` entries are optional, and, if omitted, target defaults to `dns_host_ipv4`+`dns_host_ipv6`
and `only` sets the record only in the specified zone, if omitted, the record will be created in all zones.

### CNAME records

CNAME entries can be specified in a list of dicts in `dns_cnames`, and each entry consists of an object
with the keys `zone` and `names`.
`zone` is the zone where the CNAMEs should be created, and `names` is an array of dicts describing each CNAME.
This dict has a mandatory entry called `name`, which is the CNAME itself.
It is supported to also have a key called `target`, which can be used to point the CNAME to `target`.`zone`,
the default is `dns_host_name_short`.`zone`.

### SRV records

Similar to CNAMEs, `SRV` records may be specified in `dns_services`. The mandatory keys are `name` and `port`,
other keys are `protocol` (default `tcp`), `weight` (default `10`),
`priority` (default `10`) and `target` (default `dns_host_name_short`.`zone`).
The `record` may also be specified to override the default `dns_host_name_short`.`zone`, if needed.
`{ name: matrix, port: 443}` would create f.ex. `_matrix._tcp.$dns_host_name_short.$zone 10 10 443`.

### TXT records

To create TXT records, the `dns_text_records` dict needs to be populated with `{ zone, records[] }` entries.
The specified records are then created in the given zone, and have the structure of `{ name, content }`.

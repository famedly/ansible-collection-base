# Maintenance

## Updating

When the ldap container image is updated, one needs to make
sure the config template is still up-to-date.

To do this, run `docker run --rm registry.famedly.net/docker-oss/openldap:$VERSION cat /etc/openldap/slapd.ldif > templates/slapd_$VERSION.ldif`
and use `diff templates/slapd_$VERSION templates/slapd.ldif.j2`.

When you integrated potential config changes, make sure that the
header in `templates/slapd.ldif.j2` is up-to-date AND both the
version bump and the config change are done in a SINGLE commit.

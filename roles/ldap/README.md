# openLDAP role

## Description

Deploys [`famedly/containers/openldap`](https://gitlab.com/famedly/containers/openldap),
which is openldap running in an alpine linux-based docker container.
The `core.schema`, `cosine.schema` and `inetOrgPerson.schema` are loaded by default,
and an MDB database is configured for the `ldap_domain`.

Access control lists (ACLs) can be specified in `ldap_acls` and are applied to the MDB database.
A root user can be specified and has full access on the database,
full access to the config (`cn=config`) is given to local root
(`gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth`).

An `organizationalUnit` for users and groups is created per default,
the users should be created as `uid=$userName,ou=users,$ldap_dn` with `objectClass=inetOrgPerson`,
and groups would be `cn=$groupName,ou=groups,$ldap_dn` with `objectClass=groupOfNames`.

## Requirements

Needs `python-ldap` installed for the `ldap_entry`/`ldap_attr` modules to be able to connect.
Docker daemon also needs to run and be accessable from the `ansible_user`.
The role uses privilege escalation to become host-root to be able
to set the ACLs in the container (which needs root there).

## Usage

- `ldap_domain`: Where the LDAP server runs, e.g. 'example.org'.
  The root node and it's DN are constructed from this value.

- `ldap_root_user`/`ldap_root_pass`/`ldap_root_pass_hash`: The root user
  of the database and the password in cleartext and the hashed form of the password
  which gets written into the config. The rootDN is constructed from
  `ldap_root_user`+`ldap_dn` (`ldap_dn` is constructed from `ldap_domain`).

- `ldap_org`: Name of the organization. A root node in the DIT is automatically
  created and the Organization name can be set here.

- `ldap_org_units`: Additional `organizationalUnit`s the role creates at the top
  level of the DIT. Defaults to `[ groups, users ]`.

- `ldap_additional_schemas`: Can be populated with dicts of the form
  `{name: "example.ldif", content: "schema_definition_here"}` to load those schemas
  into the ldap config tree during initial setup.

- `ldap_additional_indices`: Can be used to declare additional indices on the `mdb`
  database, like `uid eq` (maintains an equality index on the `uid` attribute).

See the [test playbook](tests/test.yml) for an example of how to use the role.

You can use `sudo ANSIBLE_ROLES_PATH="$(pwd)/roles" ansible-playbook -i roles/ldap/tests/inventory roles/ldap/tests/test.yml`
from the collection-directory to run the tests.

# Redis role

This role can be used to deploy redis in a docker container, and can be used
as a easy drop-in when an application needs a redis DB for caching/...

## Usage

The role supports prefixing all paths/users/containers with `redis_prefix`, so
the role can easily be used multiple times for different usage cases.

For securing redis additionally, a `redis_secret` can be configured. Keep in mind
that redis recommends very long secrets, as redis itself has no brute-force-
protection.

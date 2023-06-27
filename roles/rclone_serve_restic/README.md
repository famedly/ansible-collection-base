# `famedly.base.rclone_serve_restic` ansible role for multi-tenancy append-only backups to s3 using rclone

## Required Options

This role supports a single s3 bucket as a backend, you can set the required options like so
``` yml
rclone_serve_restic_backend_config:
  endpoint: "top secret"
  access_key_id: "middle secret"
  secret_access_key: "bottom secret"

  # you can just overwrite the defaults with the following
  type: s3
  provider: minio
  env_auth: false
  region: home-sweet-home
  acl: private

```

You also NEED to write secrets to the htpasswd file yourself, or else it will be exposed WITHOUT AUTHENTICATION!!
The file is read from the location set in `rclone_serve_restic_htpasswd_file`

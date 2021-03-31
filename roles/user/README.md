User Provisioning
============================

This role is provisioning access of the staff to the servers this is run on

Role Variables
--------------

The defaults/main.yml file contains a list of users in this format:
```
users:
  - name: username
    root: true|false
    ssh:
      - key: ssh key
        active: true|false
```

Users is a list of users, ssh is a list of ssh keys.

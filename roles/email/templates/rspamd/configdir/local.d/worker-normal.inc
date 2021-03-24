# /etc/rspamd/local.d/worker-normal.inc
#bind_socket = "*:{{ rspamd_listening_port }}";
bind_socket = "*:11333";
#count = 1;
#enabled = true; #default
#enabled = false; #not needed in proxy selfscan mode
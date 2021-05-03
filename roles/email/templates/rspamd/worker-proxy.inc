# /etc/rspamd/local.d/worker-proxy.inc
milter = yes; # Enable milter mode
timeout = 120s; # Needed for Milter usually
upstream "local" {
  default = yes; # Self-scan upstreams are always default
  self_scan = yes; # Enable self-scan
}

count = 4; # Spawn more processes in self-scan mode
max_retries = 5; # How many times master is queried in case of failure
discard_on_reject = false; # Discard message instead of rejection
quarantine_on_reject = false; # Tell MTA to quarantine rejected messages
spam_header = "X-Spam"; # Use the specific spam header
reject_message = "Spam message rejected"; # Use custom rejection message

bind_socket = "*:{{ rspamd_milter_listening_port }}";
#count = 1;
#enabled = true; #default
# /etc/rspamd/local.d/options.inc
#filters = "chartable,dkim,spf,surbl,regexp,fuzzy_check";
filters = "chartable,dkim,regexp";

# Local networks (default)
# skip some checks like spf
local_addrs = "{{ email_local_send_network }}";
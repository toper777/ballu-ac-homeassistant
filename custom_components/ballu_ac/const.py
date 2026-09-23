"""Constants for Ballu AC integration."""
DOMAIN = "ballu_ac"
CONF_PUBKEY = "pubkey"
DEFAULT_PORT = 41122

# Stable device identity (the IP is NOT stable — it changes with the router).
CONF_MAC = "mac"
# Frozen at entry creation/migration and never recomputed from the current IP,
# so entities and the HA device keep their identity when the address changes.
CONF_UID_BASE = "uid_base"      # entity unique_id = f"ballu_{uid_base}_{key}"
CONF_DEVICE_KEY = "device_key"  # device registry identifier (DOMAIN, device_key)

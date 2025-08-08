import fnmatch
from ibc_monitor.config import ExcludedSequences

class PacketFilter:
    """
    Wildcard-based allow/deny packet filter for clients and channels.
    rules: List of [client_pattern, channel_pattern]
    policy: 'allow' (whitelist) or 'deny' (blacklist)
    """
    def __init__(self, policy: str, rules: list[list[str]]):
        self.allow = policy.lower() == 'allow'
        self.rules = rules

    def matches(self, client: str, channel: str) -> bool:
        # If any rule matches, return allow; else return opposite
        for c_pat, ch_pat in self.rules:
            if fnmatch.fnmatch(client, c_pat) and fnmatch.fnmatch(channel, ch_pat):
                return self.allow
        return not self.allow

# Expose ExcludedSequences for convenience
ExcludedSequences = ExcludedSequences
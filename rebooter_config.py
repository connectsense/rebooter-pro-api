from typing import Dict, Any


def parse_config(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses raw config response into a validated dictionary with defaults."""
    return {
        "off_duration": data.get("off_duration", 30),
        "max_auto_reboots": data.get("max_auto_reboots", 0),
        "enable_power_fail_reboot": data.get("enable_power_fail_reboot", False),
        "enable_ping_fail_reboot": data.get("enable_ping_fail_reboot", False),
        "ping_config": {
            "any_fail_logic": data.get("ping_config", {}).get("any_fail_logic", True),
            "outage_trigger_time": data.get("ping_config", {}).get("outage_trigger_time", 5),
            "detection_delay": data.get("ping_config", {}).get("detection_delay", 2),
            "target_addrs": data.get("ping_config", {}).get("target_addrs", []),
        }
    }


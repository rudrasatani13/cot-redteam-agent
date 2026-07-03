"""
Monitors package — auto-discovers all monitor modules.
"""
from cot_redteam.monitors.base import BaseMonitor, MonitorRegistry, auto_discover_monitors
from cot_redteam.monitors.regex_monitor import RegexMonitor, RegexMonitorAdvanced
from cot_redteam.monitors.llm_judge import LLMJudgeMonitor, SelfMonitoringJudge
from cot_redteam.monitors.ensemble import EnsembleMonitor, CascadingMonitor
from cot_redteam.monitors.evasion import EvasionTestFramework

# Auto-discover on import
auto_discover_monitors()

__all__ = [
    "BaseMonitor",
    "MonitorRegistry",
    "RegexMonitor",
    "RegexMonitorAdvanced",
    "LLMJudgeMonitor",
    "SelfMonitoringJudge",
    "EnsembleMonitor",
    "CascadingMonitor",
    "EvasionTestFramework",
]
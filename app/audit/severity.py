from enum import IntEnum


class Severity(IntEnum):
    Info = 0
    Low = 1
    Medium = 2
    High = 3
    Critical = 4


SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def max_severity(*values: str) -> str:
    return max(values, key=lambda v: Severity[v])

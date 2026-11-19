"""Aggregating threat log shared by every CDR module."""
from collections import OrderedDict

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_DETAILS = 8
MAX_DETAIL_LEN = 300


class ThreatLog:
    def __init__(self):
        self._items = OrderedDict()

    def add(self, type_, risk, detail=None, count=1):
        item = self._items.setdefault(
            (type_, risk), {"type": type_, "risk": risk, "count": 0, "details": []}
        )
        item["count"] += count
        if detail is not None:
            # details can contain attacker-controlled text: truncate, stringify
            d = str(detail)[:MAX_DETAIL_LEN]
            if d not in item["details"] and len(item["details"]) < MAX_DETAILS:
                item["details"].append(d)

    def extend(self, other):
        for it in other._items.values():
            first = True
            for d in (it["details"] or [None]):
                self.add(it["type"], it["risk"], d, count=it["count"] if first else 0)
                first = False

    def to_list(self):
        return sorted(
            (dict(v) for v in self._items.values()),
            key=lambda x: (RISK_ORDER.get(x["risk"], 9), x["type"]),
        )

    def total(self):
        return sum(v["count"] for v in self._items.values())

    def has(self, type_):
        return any(k[0] == type_ for k in self._items)

    def __len__(self):
        return len(self._items)

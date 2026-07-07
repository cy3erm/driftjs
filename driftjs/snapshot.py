import hashlib
import json
import os
import time
from dataclasses import dataclass, field

from .extract import Extraction


def _state_dir(base: str, target: str) -> str:
    h = hashlib.sha256(target.encode()).hexdigest()[:12]
    d = os.path.join(base, h)
    os.makedirs(d, exist_ok=True)

    with open(os.path.join(d, "target.txt"), "w") as f:
        f.write(target)
    return d


def load_latest(base: str, target: str) -> Extraction | None:
    d = _state_dir(base, target)
    path = os.path.join(d, "latest.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    return Extraction(endpoints=set(data.get("endpoints", [])),
                      params=set(data.get("params", [])),
                      secrets={tuple(s) for s in data.get("secrets", [])},
                      sinks=set(data.get("sinks", [])),
                      sourcemaps=set(data.get("sourcemaps", [])),
                      cloud={tuple(c) for c in data.get("cloud", [])},
                      notable=set(data.get("notable", [])),
                      weaknesses={tuple(w) for w in data.get("weaknesses", [])},
                      libraries={tuple(x) for x in data.get("libraries", [])},
                      comments=set(data.get("comments", [])),
                      internal_hosts=set(data.get("internal_hosts", [])),
                      websockets=set(data.get("websockets", [])),
                      source_files=set(data.get("source_files", [])))


def save_snapshot(base: str, target: str, ex: Extraction) -> None:
    d = _state_dir(base, target)
    payload = {
        "target": target,
        "ts": int(time.time()),
        "endpoints": sorted(ex.endpoints),
        "params": sorted(ex.params),
        "secrets": sorted(list(s) for s in ex.secrets),
        "sinks": sorted(ex.sinks),
        "sourcemaps": sorted(ex.sourcemaps),
        "cloud": sorted(list(c) for c in ex.cloud),
        "notable": sorted(ex.notable),
        "weaknesses": sorted(list(w) for w in ex.weaknesses),
        "libraries": sorted(list(x) for x in ex.libraries),
        "comments": sorted(ex.comments),
        "internal_hosts": sorted(ex.internal_hosts),
        "websockets": sorted(ex.websockets),
        "source_files": sorted(ex.source_files),
    }
    stamp = time.strftime("%Y%m%d-%H%M%S")
    with open(os.path.join(d, f"{stamp}.json"), "w") as f:
        json.dump(payload, f, indent=2)
    with open(os.path.join(d, "latest.json"), "w") as f:
        json.dump(payload, f, indent=2)


_DIFF_CATS = ["endpoints", "params", "secrets", "cloud", "notable", "weaknesses",
              "sinks", "sourcemaps", "libraries", "comments", "internal_hosts",
              "websockets", "source_files"]


@dataclass
class Diff:
    new: dict = field(default_factory=dict)
    gone: dict = field(default_factory=dict)
    first_run: bool = False
    total_endpoints: int = 0

    @property
    def new_endpoints(self):
        return self.new.get("endpoints", [])

    @property
    def gone_endpoints(self):
        return self.gone.get("endpoints", [])

    @property
    def new_params(self):
        return self.new.get("params", [])

    @property
    def new_secrets(self):
        return self.new.get("secrets", [])

    @property
    def new_weaknesses(self):
        return self.new.get("weaknesses", [])

    def has_changes(self):
        return any(self.new.get(c) for c in _DIFF_CATS) or bool(self.gone.get("endpoints"))


def diff(previous: Extraction | None, current: Extraction) -> Diff:
    d = Diff(total_endpoints=len(current.endpoints))
    if previous is None:
        d.first_run = True
        for cat in _DIFF_CATS:
            d.new[cat] = sorted(getattr(current, cat))
        return d
    for cat in _DIFF_CATS:
        d.new[cat] = sorted(getattr(current, cat) - getattr(previous, cat))
    d.gone["endpoints"] = sorted(previous.endpoints - current.endpoints)
    d.gone["params"] = sorted(previous.params - current.params)
    return d

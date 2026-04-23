"""本体注册中心：系统的单一事实源。

用法：
    from core.ontology_service import get_service
    svc = get_service()
    onto = svc.get_current()
    svc.subscribe(lambda old, new: print(f"upgraded: {old} -> {new}"))

设计约束（需求文档 §4.2）：
  - YAML 存储，不用数据库（diff/git 友好）
  - 版本递增，不可修改/删除（演化硬边界）
  - 文件监听实现 hot reload
  - 所有层订阅变更事件，升级后自动响应
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

VERSION_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.yaml$")


@dataclass(frozen=True)
class Ontology:
    """不可变的本体快照。"""
    version: str
    created: str
    created_by: str
    description: str
    nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    edges: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    meta_attr_spec: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    attack_anchors: List[Dict[str, str]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: Path) -> "Ontology":
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(
            version=str(data.get("version", "")),
            created=str(data.get("created", "")),
            created_by=str(data.get("created_by", "")),
            description=str(data.get("description", "")),
            nodes=data.get("nodes") or {},
            edges=data.get("edges") or {},
            meta_attr_spec=data.get("meta_attr_spec") or {},
            attack_anchors=data.get("attack_anchors") or [],
            raw=data,
        )

    def node_types(self) -> List[str]:
        return sorted(self.nodes.keys())

    def edge_types(self) -> List[str]:
        return sorted(self.edges.keys())

    def has_node(self, node_type: str) -> bool:
        return node_type in self.nodes

    def has_edge(self, edge_type: str) -> bool:
        return edge_type in self.edges

    def required_attrs(self, node_type: str) -> List[str]:
        return list(self.nodes.get(node_type, {}).get("required_attrs") or [])

    def all_attrs(self, node_type: str) -> List[str]:
        n = self.nodes.get(node_type, {})
        return list(
            (n.get("required_attrs") or [])
            + (n.get("optional_attrs") or [])
            + (n.get("meta_attrs") or [])
        )

    def edge_endpoints(self, edge_type: str) -> Optional[tuple[str, str]]:
        e = self.edges.get(edge_type)
        if not e:
            return None
        return (str(e.get("from", "")), str(e.get("to", "")))


SubscribeCallback = Callable[[Optional[Ontology], Ontology], None]


class OntologyService:
    """注册中心服务：读取/订阅本体。

    - 支持 hot reload（watchdog 监听 ontology/ 目录）
    - 订阅者在版本变化时收到 (old, new) 回调
    - 线程安全
    """

    def __init__(self, ontology_dir: Path) -> None:
        self._dir = Path(ontology_dir)
        if not self._dir.exists():
            raise FileNotFoundError(f"Ontology dir not found: {self._dir}")
        self._lock = threading.RLock()
        self._current: Optional[Ontology] = None
        self._versions: Dict[str, Path] = {}
        self._subscribers: List[SubscribeCallback] = []
        self._observer: Optional[Observer] = None
        self._load_all()

    # -------- Public API --------

    def get_current(self) -> Ontology:
        with self._lock:
            if self._current is None:
                raise RuntimeError("No ontology loaded")
            return self._current

    def get_version(self, version: str) -> Optional[Ontology]:
        version = _normalize_version(version)
        with self._lock:
            path = self._versions.get(version)
            if path is None:
                return None
            return Ontology.from_yaml(path)

    def list_versions(self) -> List[str]:
        with self._lock:
            return sorted(self._versions.keys(), key=_version_sort_key)

    def subscribe(self, callback: SubscribeCallback) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: SubscribeCallback) -> None:
        with self._lock:
            self._subscribers = [c for c in self._subscribers if c is not callback]

    def reload(self) -> None:
        """强制重新加载（通常由文件监听触发，也可手动调用）。"""
        with self._lock:
            old = self._current
            self._load_all()
            new = self._current
            if new is not None and (old is None or old.version != new.version):
                self._notify(old, new)

    def start_watching(self) -> None:
        """启动文件监听（可选，原型阶段按需启用）。"""
        with self._lock:
            if self._observer is not None:
                return
            handler = _OntologyFileHandler(self)
            obs = Observer()
            obs.schedule(handler, str(self._dir), recursive=False)
            obs.daemon = True
            obs.start()
            self._observer = obs
            logger.info("Ontology file watcher started on %s", self._dir)

    def stop_watching(self) -> None:
        with self._lock:
            if self._observer is not None:
                self._observer.stop()
                self._observer.join(timeout=2.0)
                self._observer = None
                logger.info("Ontology file watcher stopped")

    # -------- Internal --------

    def _load_all(self) -> None:
        versions: Dict[str, Path] = {}
        for path in sorted(self._dir.glob("v*.yaml")):
            m = VERSION_PATTERN.match(path.name)
            if not m:
                continue
            try:
                onto = Ontology.from_yaml(path)
                if not onto.version:
                    logger.warning("Skipped %s: no version field", path)
                    continue
                versions[onto.version] = path
            except yaml.YAMLError as exc:
                logger.error("Failed to parse %s: %s", path, exc)
        if not versions:
            raise FileNotFoundError(f"No valid v*.yaml found in {self._dir}")
        latest = max(versions.keys(), key=_version_sort_key)
        self._versions = versions
        self._current = Ontology.from_yaml(versions[latest])

    def _notify(self, old: Optional[Ontology], new: Ontology) -> None:
        for cb in list(self._subscribers):
            try:
                cb(old, new)
            except Exception:
                logger.exception("Subscriber callback failed")


class _OntologyFileHandler(FileSystemEventHandler):
    def __init__(self, service: OntologyService) -> None:
        self._svc = service

    def on_created(self, event: FileSystemEvent) -> None:
        if self._relevant(event):
            self._svc.reload()

    def on_modified(self, event: FileSystemEvent) -> None:
        if self._relevant(event):
            self._svc.reload()

    @staticmethod
    def _relevant(event: FileSystemEvent) -> bool:
        if event.is_directory:
            return False
        return VERSION_PATTERN.match(Path(event.src_path).name) is not None


def _normalize_version(v: str) -> str:
    v = v.strip()
    if not v.startswith("v") and re.match(r"^\d", v):
        v = "v" + v
    return v


def _version_sort_key(v: str) -> tuple[int, int]:
    m = re.match(r"^v?(\d+)\.(\d+)$", v)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


# 模块级单例（按需使用）
_default_service: Optional[OntologyService] = None


def get_service(ontology_dir: Optional[Path] = None) -> OntologyService:
    """获取默认本体服务实例。"""
    global _default_service
    if _default_service is None:
        if ontology_dir is None:
            ontology_dir = Path(__file__).resolve().parents[1] / "ontology"
        _default_service = OntologyService(ontology_dir)
    return _default_service

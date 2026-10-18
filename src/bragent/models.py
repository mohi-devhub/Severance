"""Domain models every layer speaks in (docs/02)."""

from typing import Literal

from pydantic import BaseModel

EdgeType = Literal["MEMBER_OF", "HAS_ROLE", "CAN_ASSUME", "GRANTS", "PERMITS", "TARGETS"]
EDGE_TYPES: tuple[str, ...] = EdgeType.__args__


class Finding(BaseModel):
    id: str
    kind: Literal["public_write", "public_read", "overly_permissive", "exposed_secret"]
    resource_name: str
    description: str


class NodeRef(BaseModel):
    id: str
    label: str
    name: str
    kind: str | None = None  # principal kind / resource type


class EdgeRef(BaseModel):
    from_id: str
    type: EdgeType
    to_id: str


class GraphPath(BaseModel):
    nodes: list[NodeRef]
    edges: list[str]
    length: int

    @property
    def ids(self) -> list[str]:
        return [n.id for n in self.nodes]

    def edge_refs(self) -> list[EdgeRef]:
        return [
            EdgeRef(from_id=a.id, type=t, to_id=b.id)
            for a, t, b in zip(self.nodes, self.edges, self.nodes[1:], strict=False)
        ]

    def cypher_render(self) -> str:
        out = f"({self.nodes[0].name}:{self.nodes[0].kind or self.nodes[0].label})"
        for edge, node in zip(self.edges, self.nodes[1:], strict=True):
            out += f" -[{edge}]-> ({node.name}:{node.label})"
        return out


class ResourceRow(BaseModel):
    id: str
    name: str
    type: str
    sensitivity: str


class Reacher(BaseModel):
    principal: NodeRef
    kind: str
    hops: int
    via_actions: list[str]


class Broker(BaseModel):
    node: NodeRef
    score: float


class BlastRadius(BaseModel):
    reacher_count: int
    external_reacher_count: int
    shortest_external_path: GraphPath | None
    shortest_external_hops: int | None
    top_brokers: list[Broker]
    reacher_ids: list[str] = []
    severity: float = 0.0


class RemediationPlan(BaseModel):
    action: Literal["detach_policy", "revoke_assume", "remove_member", "restrict_action"]
    edge: EdgeRef
    resource_id: str
    rationale: str
    justifying_paths: list[GraphPath]
    alternatives: list[EdgeRef] = []


class DryRunResult(BaseModel):
    before: BlastRadius
    after: BlastRadius
    paths_closed: list[GraphPath]
    collateral: list[str]


class Approval(BaseModel):
    approved: bool
    approver: str
    note: str = ""
    token: str = ""

"""Parameterized graph writer shared by synthetic fixtures and IAM imports."""

from severance.graph.client import run_rw


class GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, list[dict]] = {}
        self.label: dict[str, str] = {}
        self.edges: list[tuple[str, str, str, dict]] = []

    def _node(self, label: str, **props) -> str:
        if props["id"] not in self.label:
            self.nodes.setdefault(label, []).append(props)
            self.label[props["id"]] = label
        return props["id"]

    def principal(self, id: str, name: str, kind: str) -> str:
        return self._node("Principal", id=id, name=name, kind=kind)

    def role(self, id: str, name: str, trust: str = "internal") -> str:
        return self._node("Role", id=id, name=name, trust=trust)

    def policy(self, id: str, name: str, managed: bool = True) -> str:
        return self._node("Policy", id=id, name=name, managed=managed)

    def resource(self, id: str, name: str, type: str, sensitivity: str) -> str:
        return self._node("Resource", id=id, name=name, type=type, sensitivity=sensitivity)

    def action(self, name: str, resource_id: str, access: str) -> str:
        aid = f"{name}@{resource_id}"
        if aid not in self.label:
            self._node("Action", id=aid, name=name)
            self.edge(aid, "TARGETS", resource_id, access=access)
        return aid

    def edge(self, f: str, type: str, t: str, **props) -> None:
        if type == "PERMITS":
            props.setdefault("effect", "allow")
        self.edges.append((f, type, t, props))

    def write(self) -> None:
        for label, rows in self.nodes.items():
            run_rw(f"UNWIND $rows AS r CREATE (n:{label}) SET n = r", {"rows": rows})
        groups: dict[tuple, list[dict]] = {}
        for f, type, t, props in self.edges:
            key = (self.label[f], type, self.label[t])
            groups.setdefault(key, []).append({"f": f, "t": t, "props": props})
        for (fl, type, tl), rows in groups.items():
            run_rw(
                f"UNWIND $rows AS r MATCH (a:{fl} {{id: r.f}}), (b:{tl} {{id: r.t}}) "
                f"CREATE (a)-[e:{type}]->(b) SET e += r.props",
                {"rows": rows},
            )

    @property
    def node_count(self) -> int:
        return len(self.label)

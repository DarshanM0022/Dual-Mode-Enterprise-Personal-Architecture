import networkx as nx
from typing import Dict, Any, List, Optional
import json
from src.database.db import get_connection

class EntityGraphEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self._build_initial_graph()

    def _build_initial_graph(self):
        """
        Loads all entities, incidents, and relationships into NetworkX
        """
        self.graph.clear()
        conn = get_connection()
        cursor = conn.cursor()

        # 1. Add Users
        cursor.execute("SELECT user_id, full_name, role, privilege_level, risk_score FROM entities_user")
        for u in cursor.fetchall():
            self.graph.add_node(
                u["user_id"],
                label=u["full_name"],
                type="USER",
                sublabel=u["role"],
                risk=u["risk_score"],
                color="#f43f5e" if u["risk_score"] > 60 else ("#f59e0b" if u["risk_score"] > 30 else "#10b981")
            )

        # 2. Add Devices
        cursor.execute("SELECT device_id, hostname, os_type, owner_user_id, risk_score, status FROM entities_device")
        for d in cursor.fetchall():
            self.graph.add_node(
                d["device_id"],
                label=d["hostname"],
                type="DEVICE",
                sublabel=d["os_type"],
                risk=d["risk_score"],
                status=d["status"],
                color="#f43f5e" if d["risk_score"] > 60 else ("#f59e0b" if d["risk_score"] > 30 else "#3b82f6")
            )
            # Edge: Owner -> Device
            if d["owner_user_id"] and self.graph.has_node(d["owner_user_id"]):
                self.graph.add_edge(d["owner_user_id"], d["device_id"], relationship="OWNS_DEVICE")

        # 3. Add Applications
        cursor.execute("SELECT app_id, name, category, criticality, risk_score FROM entities_app")
        for a in cursor.fetchall():
            self.graph.add_node(
                a["app_id"],
                label=a["name"],
                type="APPLICATION",
                sublabel=a["criticality"],
                risk=a["risk_score"],
                color="#8b5cf6"
            )

        # 4. Add Incidents
        cursor.execute("SELECT incident_id, title, severity, blast_radius_score, raw_json FROM incidents")
        for inc in cursor.fetchall():
            self.graph.add_node(
                inc["incident_id"],
                label=inc["title"][:28] + "...",
                type="INCIDENT",
                sublabel=inc["severity"],
                risk=inc["blast_radius_score"],
                color="#ef4444"
            )
            data = json.loads(inc["raw_json"])
            for aff in data.get("affected_entities", []):
                ent_id = aff.get("id")
                if ent_id:
                    if not self.graph.has_node(ent_id):
                        self.graph.add_node(
                            ent_id,
                            label=aff.get("name", ent_id),
                            type=aff.get("type", "UNKNOWN"),
                            risk=75.0,
                            color="#f59e0b"
                        )
                    self.graph.add_edge(inc["incident_id"], ent_id, relationship="IMPLICATED_IN")

        # 5. Connect known interactions from recent events
        cursor.execute("SELECT actor_id, source_id, dest_name FROM events ORDER BY timestamp DESC LIMIT 100")
        for ev in cursor.fetchall():
            u_id = ev["actor_id"]
            d_id = ev["source_id"]
            if u_id and d_id and self.graph.has_node(u_id) and self.graph.has_node(d_id):
                if not self.graph.has_edge(u_id, d_id):
                    self.graph.add_edge(u_id, d_id, relationship="AUTHENTICATED_FROM")

        # Explicit known enterprise connections
        if self.graph.has_node("usr-elena-finance") and self.graph.has_node("app-netsuite"):
            self.graph.add_edge("usr-elena-finance", "app-netsuite", relationship="ACCESSED_RECORDS")
        if self.graph.has_node("usr-marcus-sec") and self.graph.has_node("app-okta-idp"):
            self.graph.add_edge("usr-marcus-sec", "app-okta-idp", relationship="ADMINISTERS")
        if self.graph.has_node("usr-alex-dev") and self.graph.has_node("app-github-ent"):
            self.graph.add_edge("usr-alex-dev", "app-github-ent", relationship="COMMITS_TO")
        if self.graph.has_node("usr-alex-dev") and self.graph.has_node("app-aws-prod"):
            self.graph.add_edge("usr-alex-dev", "app-aws-prod", relationship="MANAGES_INFRA")

        conn.close()

    def get_visjs_graph_data(self) -> Dict[str, Any]:
        """
        Formats network graph for rendering in Vis.js frontend
        """
        self._build_initial_graph()
        nodes = []
        edges = []

        type_shapes = {
            "USER": "dot",
            "DEVICE": "square",
            "APPLICATION": "diamond",
            "INCIDENT": "triangle",
            "IP": "star"
        }

        for node_id, data in self.graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                "label": f"{data.get('label', node_id)}\n({data.get('type', 'NODE')})",
                "title": f"Type: {data.get('type')}<br>Risk: {data.get('risk')}/100<br>Detail: {data.get('sublabel')}",
                "color": data.get("color", "#64748b"),
                "shape": type_shapes.get(data.get("type", "USER"), "dot"),
                "value": max(15, min(int(data.get("risk", 20)), 50)),
                "entityType": data.get("type")
            })

        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "from": u,
                "to": v,
                "label": data.get("relationship", "CONNECTED"),
                "arrows": "to",
                "color": {"color": "#475569", "highlight": "#06b6d4"}
            })

        return {"nodes": nodes, "edges": edges}

    def compute_blast_radius(self, target_node_id: str, max_hops: int = 2) -> Dict[str, Any]:
        """
        Computes the blast radius (all directly and indirectly exposed assets) around an entity
        """
        self._build_initial_graph()
        if not self.graph.has_node(target_node_id):
            return {"error": f"Node {target_node_id} not found in graph", "reachable_nodes": [], "score": 0.0}

        # Calculate ego graph (neighborhood up to max_hops)
        subgraph = nx.ego_graph(self.graph, target_node_id, radius=max_hops)
        reachable = []
        total_risk_impact = 0.0

        for n in subgraph.nodes():
            if n != target_node_id:
                ndata = self.graph.nodes[n]
                reachable.append({
                    "id": n,
                    "label": ndata.get("label", n),
                    "type": ndata.get("type", "UNKNOWN"),
                    "risk": ndata.get("risk", 10.0),
                    "hops": nx.shortest_path_length(subgraph, target_node_id, n)
                })
                total_risk_impact += ndata.get("risk", 10.0)

        # Blast radius score calculation
        blast_score = round(min(100.0, (len(reachable) * 12.0) + (total_risk_impact / max(len(reachable), 1) * 0.5)), 1)

        return {
            "target": target_node_id,
            "max_hops": max_hops,
            "blast_radius_score": blast_score,
            "exposed_asset_count": len(reachable),
            "reachable_assets": sorted(reachable, key=lambda x: x["hops"])
        }

entity_graph = EntityGraphEngine()

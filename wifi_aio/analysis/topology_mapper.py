"""TopologyMapper – network topology with DOT / Mermaid / HTML output.

Builds a graph of wireless network topology (APs, clients, connections)
and exports it in multiple visualisation formats.
"""

import html
import json
from collections import defaultdict
from typing import Dict, List, Optional, Set

from wifi_aio.exceptions import WiFiConnectionError
from wifi_aio.logger import get_logger

logger = get_logger("analysis.topology_mapper")


class TopologyNode:
    """A node in the network topology graph.

    Attributes
    ----------
    id:
        Unique identifier (typically BSSID or MAC).
    label:
        Human-readable label (SSID, hostname, etc.).
    node_type:
        ``"ap"``, ``"client"``, or ``"switch"``.
    attributes:
        Additional key-value pairs (signal, channel, security, …).
    """

    __slots__ = ("id", "label", "node_type", "attributes")

    def __init__(
        self,
        node_id: str,
        label: str = "",
        node_type: str = "ap",
        **attributes: object,
    ) -> None:
        self.id = node_id
        self.label = label or node_id
        self.node_type = node_type
        self.attributes = attributes

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type,
            **self.attributes,
        }


class TopologyEdge:
    """An edge connecting two topology nodes.

    Attributes
    ----------
    source:
        Source node ID.
    target:
        Target node ID.
    label:
        Optional edge label (e.g. ``"associated"``, ``"probing"``).
    attributes:
        Additional key-value pairs.
    """

    __slots__ = ("source", "target", "label", "attributes")

    def __init__(
        self,
        source: str,
        target: str,
        label: str = "",
        **attributes: object,
    ) -> None:
        self.source = source
        self.target = target
        self.label = label
        self.attributes = attributes

    def to_dict(self) -> Dict[str, object]:
        d: Dict[str, object] = {"source": self.source, "target": self.target}
        if self.label:
            d["label"] = self.label
        d.update(self.attributes)
        return d


class TopologyMapper:
    """Build and export wireless network topology graphs.

    Parameters
    ----------
    title:
        Title for the generated diagrams.
    """

    def __init__(self, title: str = "WiFi Network Topology") -> None:
        self.title = title
        self._nodes: Dict[str, TopologyNode] = {}
        self._edges: List[TopologyEdge] = []

    # ── Building the graph ─────────────────────────────────────────────

    def add_node(self, node_id: str, label: str = "", node_type: str = "ap", **attrs: object) -> TopologyNode:
        """Add a node to the topology graph.

        If a node with *node_id* already exists, its attributes are
        updated but the type and label are preserved.
        """
        if node_id in self._nodes:
            node = self._nodes[node_id]
            node.attributes.update(attrs)
            return node
        node = TopologyNode(node_id, label, node_type, **attrs)
        self._nodes[node_id] = node
        return node

    def add_edge(self, source: str, target: str, label: str = "", **attrs: object) -> TopologyEdge:
        """Add an edge between two nodes.

        Nodes are created automatically if they do not exist.
        """
        if source not in self._nodes:
            self.add_node(source, node_type="unknown")
        if target not in self._nodes:
            self.add_node(target, node_type="unknown")
        edge = TopologyEdge(source, target, label, **attrs)
        self._edges.append(edge)
        return edge

    def add_scan_results(self, scan_results: List[Dict]) -> int:
        """Add AP nodes from scan results.

        Each AP is added as a node; BSSID is used as the node ID.

        Returns the number of APs added.
        """
        count = 0
        for ap in scan_results:
            bssid = ap.get("bssid", "").lower()
            if not bssid:
                continue
            self.add_node(
                bssid,
                label=ap.get("ssid", bssid),
                node_type="ap",
                channel=ap.get("channel", 0),
                signal=ap.get("signal_dbm", 0),
                security=ap.get("security", ""),
            )
            count += 1
        return count

    def add_clients(self, clients: List[Dict]) -> int:
        """Add client nodes and edges from client records.

        Each client dict should have ``"mac"`` and optionally
        ``"associated_bssid"`` and ``"hostname"``.
        """
        count = 0
        for client in clients:
            mac = client.get("mac", "").lower()
            if not mac:
                continue
            self.add_node(
                mac,
                label=client.get("hostname", mac),
                node_type="client",
                ip=client.get("ip", ""),
            )
            bssid = client.get("associated_bssid", "").lower()
            if bssid:
                self.add_edge(mac, bssid, label="associated")
            count += 1
        return count

    # ── Queries ────────────────────────────────────────────────────────

    def get_nodes(self) -> List[TopologyNode]:
        return list(self._nodes.values())

    def get_edges(self) -> List[TopologyEdge]:
        return list(self._edges)

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return len(self._edges)

    # ── DOT (Graphviz) export ──────────────────────────────────────────

    def to_dot(self) -> str:
        """Generate a Graphviz DOT representation of the topology.

        Returns a string that can be rendered with ``dot -Tpng``.
        """
        lines: List[str] = [
            f'graph "{self.title}" {{',
            '  rankdir=TB;',
            '  node [fontname="Arial", fontsize=10];',
        ]

        # Node styles by type
        type_styles = {
            "ap":     '[shape=box, style=filled, fillcolor="#4CAF50", fontcolor=white]',
            "client": '[shape=ellipse, style=filled, fillcolor="#2196F3", fontcolor=white]',
            "switch": '[shape=diamond, style=filled, fillcolor="#FF9800", fontcolor=white]',
            "unknown": '[shape=plaintext]',
        }

        for node in self._nodes.values():
            style = type_styles.get(node.node_type, type_styles["unknown"])
            safe_label = node.label.replace('"', '\\"')
            lines.append(f'  "{safe_label}" {style}')

        for edge in self._edges:
            src_label = self._nodes[edge.source].label.replace('"', '\\"')
            tgt_label = self._nodes[edge.target].label.replace('"', '\\"')
            if edge.label:
                lines.append(f'  "{src_label}" -- "{tgt_label}" [label="{edge.label}"];')
            else:
                lines.append(f'  "{src_label}" -- "{tgt_label}";')

        lines.append("}")
        return "\n".join(lines)

    # ── Mermaid export ─────────────────────────────────────────────────

    def to_mermaid(self) -> str:
        """Generate a Mermaid flowchart representation.

        Returns a string suitable for Markdown / HTML rendering.
        """
        lines: List[str] = ["graph TD"]

        # Mermaid-safe IDs (replace non-alphanumeric with _)
        def safe_id(node_id: str) -> str:
            return "".join(c if c.isalnum() else "_" for c in node_id)

        id_map: Dict[str, str] = {}
        for node in self._nodes.values():
            sid = safe_id(node.id)
            id_map[node.id] = sid
            icon = {"ap": "📡", "client": "📱", "switch": "🔀"}.get(node.node_type, "❓")
            safe_label = node.label.replace('"', "'")
            lines.append(f'  {sid}["{icon} {safe_label}"]')

        for edge in self._edges:
            src = id_map.get(edge.source, safe_id(edge.source))
            tgt = id_map.get(edge.target, safe_id(edge.target))
            if edge.label:
                lines.append(f'  {src} -->|{edge.label}| {tgt}')
            else:
                lines.append(f'  {src} --> {tgt}')

        return "\n".join(lines)

    # ── HTML export ────────────────────────────────────────────────────

    def to_html(self) -> str:
        """Generate a standalone HTML page with an embedded Mermaid diagram."""
        mermaid_code = self.to_mermaid()
        escaped = html.escape(mermaid_code)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(self.title)}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<style>
  body {{ font-family: Arial, sans-serif; margin: 2rem; background: #1e1e1e; color: #ddd; }}
  h1 {{ color: #4CAF50; }}
  .mermaid {{ background: #2d2d2d; padding: 1rem; border-radius: 8px; }}
</style>
</head>
<body>
<h1>{html.escape(self.title)}</h1>
<div class="mermaid">
{escaped}
</div>
<script>mermaid.initialize({{startOnLoad:true,theme:"dark"}});</script>
</body>
</html>"""

    # ── JSON export ────────────────────────────────────────────────────

    def to_json(self, indent: int = 2) -> str:
        """Export the topology as a JSON string."""
        data = {
            "title": self.title,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }
        return json.dumps(data, indent=indent)

    # ── File export helpers ────────────────────────────────────────────

    def export_dot(self, path: str) -> str:
        """Write the DOT representation to a file."""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_dot())
        logger.info("DOT topology exported to %s", path)
        return path

    def export_mermaid(self, path: str) -> str:
        """Write the Mermaid representation to a file."""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_mermaid())
        logger.info("Mermaid topology exported to %s", path)
        return path

    def export_html(self, path: str) -> str:
        """Write a standalone HTML page with the topology diagram."""
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_html())
        logger.info("HTML topology exported to %s", path)
        return path

    def export_json(self, path: str) -> str:
        """Write the JSON representation to a file."""
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        logger.info("JSON topology exported to %s", path)
        return path

    # ── Clear / summary ────────────────────────────────────────────────

    def clear(self) -> None:
        """Remove all nodes and edges."""
        self._nodes.clear()
        self._edges.clear()

    def summary(self) -> Dict[str, object]:
        """Return a summary of the topology graph."""
        type_counts: Dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type] += 1

        return {
            "title": self.title,
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "node_types": dict(type_counts),
        }

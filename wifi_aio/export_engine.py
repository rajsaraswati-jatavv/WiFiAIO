"""Export engine for WiFiAIO — JSON, CSV, XML, HTML."""

import csv
import io
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString

from wifi_aio.exceptions import WiFiAIOError

logger = logging.getLogger(__name__)


class ExportEngine:
    """Export data to various formats: JSON, CSV, XML, HTML."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(
            os.path.expanduser(output_dir or "/tmp/wifi_aio/exports")
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export(
        self,
        data: Union[List[Dict], Dict],
        format: str,
        filename: Optional[str] = None,
        title: str = "WiFiAIO Export",
        **kwargs,
    ) -> str:
        """Export data to the specified format.

        Args:
            data: Data to export (list of dicts or single dict).
            format: Export format ('json', 'csv', 'xml', 'html').
            filename: Output filename (without extension). Auto-generated if None.
            title: Title for the document.
            **kwargs: Additional format-specific options.

        Returns:
            Path to the exported file.

        Raises:
            WiFiAIOError: If the format is unsupported or export fails.
        """
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_aio_export_{ts}"

        format = format.lower().strip(".")

        exporters = {
            "json": self._export_json,
            "csv": self._export_csv,
            "xml": self._export_xml,
            "html": self._export_html,
        }

        exporter = exporters.get(format)
        if exporter is None:
            raise WiFiAIOError(f"Unsupported export format: '{format}'. Supported: {list(exporters.keys())}")

        filepath = self.output_dir / f"{filename}.{format}"

        try:
            exporter(data, filepath, title=title, **kwargs)
            logger.info("Exported data to %s", filepath)
            return str(filepath)
        except Exception as exc:
            raise WiFiAIOError(f"Export to {format} failed: {exc}") from exc

    def export_json(
        self,
        data: Union[List[Dict], Dict],
        filename: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Convenience method to export as JSON."""
        return self.export(data, "json", filename, **kwargs)

    def export_csv(
        self,
        data: List[Dict],
        filename: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Convenience method to export as CSV."""
        return self.export(data, "csv", filename, **kwargs)

    def export_xml(
        self,
        data: Union[List[Dict], Dict],
        filename: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Convenience method to export as XML."""
        return self.export(data, "xml", filename, **kwargs)

    def export_html(
        self,
        data: Union[List[Dict], Dict],
        filename: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Convenience method to export as HTML."""
        return self.export(data, "html", filename, **kwargs)

    # ── Format Implementations ────────────────────────────────────────

    def _export_json(
        self,
        data: Union[List[Dict], Dict],
        filepath: Path,
        title: str = "",
        indent: int = 2,
        **kwargs,
    ) -> None:
        """Write data as JSON."""
        export_data = {
            "title": title,
            "exported_at": datetime.now().isoformat(),
            "generator": "WiFiAIO",
            "data": data,
        }
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(export_data, fh, indent=indent, ensure_ascii=False, default=str)

    def _export_csv(
        self,
        data: Union[List[Dict], Dict],
        filepath: Path,
        title: str = "",
        **kwargs,
    ) -> None:
        """Write data as CSV.

        If *data* is a dict, it's wrapped in a list.
        """
        if isinstance(data, dict):
            rows = [data]
        else:
            rows = data

        if not rows:
            # Write empty CSV with header comment
            with open(filepath, "w", encoding="utf-8", newline="") as fh:
                fh.write(f"# {title}\n")
                fh.write("# No data\n")
            return

        # Collect all fieldnames across all rows
        fieldnames = list(dict.fromkeys(k for row in rows for k in row.keys()))

        with open(filepath, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    def _export_xml(
        self,
        data: Union[List[Dict], Dict],
        filepath: Path,
        title: str = "",
        **kwargs,
    ) -> None:
        """Write data as XML."""
        root = Element("wifi_aio_export")
        SubElement(root, "title").text = title
        SubElement(root, "exported_at").text = datetime.now().isoformat()
        SubElement(root, "generator").text = "WiFiAIO"

        data_element = SubElement(root, "data")
        if isinstance(data, list):
            for item in data:
                self._dict_to_xml(item, SubElement(data_element, "item"))
        else:
            self._dict_to_xml(data, data_element)

        # Pretty print
        rough_string = tostring(root, encoding="unicode", xml_declaration=False)
        reparsed = parseString(rough_string)
        pretty = reparsed.toprettyxml(indent="  ", encoding=None)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(pretty)

    def _export_html(
        self,
        data: Union[List[Dict], Dict],
        filepath: Path,
        title: str = "",
        **kwargs,
    ) -> None:
        """Write data as an HTML document with a styled table."""
        if isinstance(data, dict):
            rows = [data]
        else:
            rows = data

        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_html_escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         margin: 2rem; background: #1e1e2e; color: #cdd6f4; }}
  h1 {{ color: #89b4fa; }}
  h2 {{ color: #a6adc8; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th {{ background: #313244; color: #89b4fa; padding: 0.75rem; text-align: left; }}
  td {{ border-bottom: 1px solid #45475a; padding: 0.75rem; }}
  tr:nth-child(even) {{ background: #1e1e2e; }}
  tr:nth-child(odd) {{ background: #252540; }}
  tr:hover {{ background: #313244; }}
  .meta {{ color: #6c7086; font-size: 0.85rem; margin-top: 2rem; }}
  .badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }}
  .critical {{ background: #f38ba8; color: #1e1e2e; }}
  .high {{ background: #fab387; color: #1e1e2e; }}
  .medium {{ background: #f9e2af; color: #1e1e2e; }}
  .low {{ background: #a6e3a1; color: #1e1e2e; }}
  .info {{ background: #89dceb; color: #1e1e2e; }}
</style>
</head>
<body>
<h1>{_html_escape(title)}</h1>
<p>Generated by WiFiAIO on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
"""

        if rows:
            fieldnames = list(dict.fromkeys(k for row in rows for k in row.keys()))
            html += "<table>\n<thead>\n<tr>\n"
            for field in fieldnames:
                html += f"<th>{_html_escape(field)}</th>\n"
            html += "</tr>\n</thead>\n<tbody>\n"
            for row in rows:
                html += "<tr>\n"
                for field in fieldnames:
                    value = str(row.get(field, ""))
                    # Add severity badge for known severity fields
                    if field in ("severity", "risk", "security_risk") and value.lower() in (
                        "critical", "high", "medium", "low", "info", "minimal"
                    ):
                        html += f'<td><span class="badge {value.lower()}">{_html_escape(value)}</span></td>\n'
                    else:
                        html += f"<td>{_html_escape(value)}</td>\n"
                html += "</tr>\n"
            html += "</tbody>\n</table>\n"
        else:
            html += "<p>No data to display.</p>\n"

        html += """
<div class="meta">Exported by WiFiAIO — All-in-One WiFi Security Toolkit</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _dict_to_xml(data: Dict, parent: Element) -> None:
        """Recursively convert a dict to XML elements."""
        for key, value in data.items():
            # Sanitize key for XML
            tag = key.replace(" ", "_").replace("/", "_")
            if not tag or tag[0].isdigit():
                tag = f"field_{tag}"
            child = SubElement(parent, tag)
            if isinstance(value, dict):
                ExportEngine._dict_to_xml(value, child)
            elif isinstance(value, list):
                for item in value:
                    item_elem = SubElement(child, "item")
                    if isinstance(item, dict):
                        ExportEngine._dict_to_xml(item, item_elem)
                    else:
                        item_elem.text = str(item)
            else:
                child.text = str(value) if value is not None else ""


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

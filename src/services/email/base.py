from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES_DIR = Path(__file__).parents[3] / "data" / "templates"


class EmailTransport:
    """
    Wrapper autour de ext.email utilisant Jinja2 pour le rendu des templates.

    Tous les emails sont envoyés via queue() (fire-and-forget, non bloquant).
    Les templates HTML sont dans app/xauth/data/templates/.
    """

    def __init__(self, email_ext: Any, app_base_url: str, app_name: str) -> None:
        self._ext = email_ext
        self.base_url = app_base_url.rstrip("/")
        self.app_name = app_name
        self._jinja = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def _render(self, template_name: str, context: dict) -> str:
        context.setdefault("app_name", self.app_name)
        return self._jinja.get_template(f"{template_name}.html").render(**context)

    def queue(self, to: str, subject: str, template: str, context: dict) -> bool:
        """Rend le template Jinja2 et l'envoie en fire-and-forget via ext.email."""
        html = self._render(template, context)
        return self._ext.queue(to=to, subject=subject, body=html, is_html=True)

from __future__ import annotations

from typing import Any


class EmailTransport:
    """
    Wrapper mince autour de l'extension email Xcore.
    Toutes les classes d'envoi héritent de cette base — remplacer
    l'extension ici suffit pour changer le transport (SMTP, SES, Resend…).
    """

    def __init__(self, email_ext: Any, app_base_url: str, app_name: str) -> None:
        self._ext = email_ext
        self.base_url = app_base_url.rstrip("/")
        self.app_name = app_name

    async def send(
        self,
        to: str,
        subject: str,
        template: str,
        context: dict,
    ) -> bool:
        context.setdefault("app_name", self.app_name)
        return await self._ext.send_template(
            to=to,
            template=template,
            subject=subject,
            context=context,
        )

    def queue(self, to: str, subject: str, body: str, is_html: bool = True) -> bool:
        """Fire-and-forget — non bloquant."""
        return self._ext.queue(to=to, subject=subject, body=body, is_html=is_html)

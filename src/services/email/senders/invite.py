from __future__ import annotations

from ..base import EmailTransport


class InviteEmailSender(EmailTransport):
    """Emails liés aux invitations."""

    def send_invitation(
        self,
        to: str,
        invite_token: str,
        inviter_name: str,
        expires_days: int = 3,
    ) -> bool:
        invite_url = f"{self.base_url}/xauth/invites/accept?token={invite_token}"
        return self.queue(
            to=to,
            subject=f"Invitation à rejoindre {self.app_name}",
            template="invitation",
            context={
                "inviter_name": inviter_name,
                "invite_url": invite_url,
                "expires_in_days": expires_days,
            },
        )

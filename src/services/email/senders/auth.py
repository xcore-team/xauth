from __future__ import annotations

from ..base import EmailTransport


class AuthEmailSender(EmailTransport):
    """Emails liés à l'inscription et à la connexion OAuth."""

    def welcome(self, to: str, username: str) -> bool:
        return self.queue(
            to=to,
            subject=f"Bienvenue sur {self.app_name} 🎉",
            template="welcome",
            context={"username": username},
        )

    def oauth_linked(self, to: str, username: str, provider: str) -> bool:
        return self.queue(
            to=to,
            subject=f"Compte {provider} lié à votre profil",
            template="oauth_linked",
            context={
                "username": username,
                "provider": provider.capitalize(),
            },
        )

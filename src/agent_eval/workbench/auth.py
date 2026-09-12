"""Online OIDC-provider token introspection with per-request revocation checks.

The provider must offer RFC 7662 introspection with issuer, audience, subject and
expiry. Browser sign-in/token acquisition belongs to the operator's OIDC client.
"""

from __future__ import annotations

import base64
import time
import urllib.parse
import urllib.request

from ..blackbox.models import parse_json
from .store import Denied


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class OIDC:
    def __init__(self, *, endpoint, issuer, audience, client_id, client_secret):
        for value in (endpoint, issuer):
            url = urllib.parse.urlsplit(value)
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username
                or url.password
                or url.fragment
            ):
                raise ValueError(
                    "OIDC requires fixed HTTPS issuer and introspection endpoint"
                )
        if not all((audience, client_id, client_secret)):
            raise ValueError("OIDC configuration incomplete")
        self.endpoint, self.issuer, self.audience = endpoint, issuer, audience
        self.authorization = (
            "Basic "
            + base64.b64encode(
                (
                    urllib.parse.quote(client_id, safe="")
                    + ":"
                    + urllib.parse.quote(client_secret, safe="")
                ).encode()
            ).decode()
        )

    def authenticate(self, token):
        if not token or len(token) > 16384:
            raise Denied("invalid credential")
        request = urllib.request.Request(
            self.endpoint,
            data=urllib.parse.urlencode({"token": token}).encode(),
            headers={
                "Authorization": self.authorization,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with urllib.request.build_opener(NoRedirect).open(
                request, timeout=5
            ) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError
                claims = parse_json(raw)
            audience = claims.get("aud")
            if isinstance(audience, str):
                audience = [audience]
            if (
                claims.get("active") is not True
                or claims.get("iss") != self.issuer
                or not isinstance(audience, list)
                or self.audience not in audience
                or not isinstance(claims.get("sub"), str)
                or not claims["sub"]
                or type(claims.get("exp")) not in (int, float)
                or claims["exp"] <= time.time()
                or claims.get("nbf", 0) > time.time()
            ):
                raise ValueError
            return self.issuer + "#" + claims["sub"]
        except Exception:
            raise Denied("OIDC credential could not be verified") from None

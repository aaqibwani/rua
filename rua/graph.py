"""Microsoft Graph client.

Client-credentials flow against one tenant. Two permissions:

* ``Mail.Read`` — read the report attachments in the shared mailbox.
* ``Domain.Read.All`` — read the tenant's verified domain list.

``Mail.Read`` rather than ``Mail.ReadBasic``. Microsoft's permissions reference is
explicit that ``Mail.ReadBasic`` "Includes all properties **except body,
previewBody, attachments**", and DMARC aggregate reports arrive as compressed XML
attachments — so ``Mail.ReadBasic`` cannot perform this product's core operation
at all. The security property that matters is unchanged: the app is scoped to one
mailbox, by App RBAC or by a legacy application access policy, and
:meth:`GraphClient.test_mailbox` is what proves it.

Synchronous, using ``httpx.Client``. The scheduler, the DNS checker and the report
parser are all synchronous; FastAPI runs sync path operations in a threadpool, so
one implementation serves both rather than two dialects of the same thing.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

from rua.logging import get_logger

log = get_logger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Which permissions must appear in the token's `roles` claim depends on how the
# app was scoped, and getting this wrong locks out the recommended path.
#
# The claim reflects Entra grants only. Under RBAC for Applications, Mail.Read is
# assigned in Exchange and deliberately NOT in Entra — granting it in both places
# unions an unscoped grant with the scoped one and defeats the scoping entirely.
# So a correctly-configured RBAC tenant presents a token carrying only
# Domain.Read.All, and requiring Mail.Read here would fail every such tenant.
#
# Mail.Read is not taken on trust in that mode: the step-4 mailbox probe is what
# proves it, and it proves the scoping at the same time.
ENTRA_PERMISSIONS_RBAC = ("Domain.Read.All",)
ENTRA_PERMISSIONS_POLICY = ("Mail.Read", "Domain.Read.All")

# Graph is not fast, and a hung setup wizard is worse than a failed one.
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)

# Exchange caches app permission changes for 30 minutes to 2 hours. A 403 shortly
# after configuring scoping is very often just the cache, not a misconfiguration,
# and telling an operator to "check your permissions" in that window sends them
# chasing a problem that does not exist.
_RBAC_CACHE_HINT = (
    "Exchange caches application permission changes for 30 minutes to 2 hours. "
    "If you have only just configured scoping, wait and try again. "
    "Test-ServicePrincipalAuthorization bypasses the cache if you want to confirm now."
)


# A very busy mailbox should not make one run unbounded. At 50 messages a page
# this is 10,000 messages; the next run picks up where this one stopped.
MAX_MESSAGE_PAGES = 200


class GraphError(RuntimeError):
    """A Graph call failed in a way the operator needs to see."""


@dataclass(frozen=True, slots=True)
class MailMessage:
    id: str
    subject: str
    received: dt.datetime
    has_attachments: bool


@dataclass(frozen=True, slots=True)
class MailAttachment:
    name: str
    content_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class GraphCredentials:
    tenant_id: str
    client_id: str
    client_secret: str

    def __repr__(self) -> str:
        # Never let the secret reach a log line, a traceback or an f-string.
        return (
            f"GraphCredentials(tenant_id={self.tenant_id!r}, "
            f"client_id={self.client_id!r}, client_secret=<redacted>)"
        )


@dataclass
class TokenTest:
    """Result of the wizard's "Test connection" step."""

    ok: bool
    tenant_domain: str | None = None
    grant_type: str = "client_credentials"
    permissions: list[str] = field(default_factory=list)
    missing_permissions: list[str] = field(default_factory=list)
    error: str | None = None

    def facts(self) -> list[dict[str, str]]:
        """The success panel rows, in the order the design shows them."""
        return [
            {"k": "Tenant", "v": self.tenant_domain or "unknown"},
            {"k": "Token acquired", "v": self.grant_type},
            {"k": "Permissions granted", "v": ", ".join(self.permissions) or "none"},
        ]


@dataclass
class MailboxTest:
    """Result of the wizard's "Verify access" step."""

    ok: bool
    message_count: int | None = None
    oldest: dt.datetime | None = None
    newest: dt.datetime | None = None
    error: str | None = None

    def facts(self) -> list[dict[str, str]]:
        return [
            {
                "k": "Messages in mailbox",
                "v": f"{self.message_count:,}" if self.message_count is not None else "unknown",
            },
            {"k": "Oldest report", "v": self.oldest.date().isoformat() if self.oldest else "none"},
            {"k": "Newest report", "v": _relative(self.newest) if self.newest else "none"},
            # The design copy read "this mailbox only". That overstates what this
            # check establishes: opening one mailbox proves access TO it, not the
            # absence of access to every other. Exclusivity is enforced by the
            # Exchange scoping assignment, and the operator confirms it with
            # Test-ServicePrincipalAuthorization / Test-ApplicationAccessPolicy —
            # which the step-2 script already tells them to run.
            {"k": "Access scope", "v": "verified for this mailbox"},
        ]


def _relative(when: dt.datetime) -> str:
    """ "14 minutes ago" — the design uses relative phrasing for the newest report."""
    delta = dt.datetime.now(dt.UTC) - when
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if seconds < 86400:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = seconds // 86400
    return f"{days} day{'s' if days != 1 else ''} ago"


def _decode_roles(access_token: str) -> list[str]:
    """Read the ``roles`` claim from the access token.

    The token is parsed, not validated: it arrived over TLS directly from the
    issuer moments ago, and we are reading it only to tell the operator which
    permissions were actually granted. Nothing is authorised on the basis of it.
    """
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore stripped padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError):
        log.warning("graph_token_claims_unreadable")
        return []
    roles = claims.get("roles", [])
    return sorted(roles) if isinstance(roles, list) else []


class GraphClient:
    """A thin Graph client scoped to what this product actually needs."""

    def __init__(self, credentials: GraphCredentials, timeout: httpx.Timeout | None = None) -> None:
        self._credentials = credentials
        self._timeout = timeout or DEFAULT_TIMEOUT
        self._token: str | None = None
        self._expires_at: dt.datetime | None = None

    # ─── Token ───────────────────────────────────────────────────────────

    def acquire_token(self, force: bool = False) -> str:
        """Return a bearer token, fetching a new one when the cached one is stale.

        Refreshed 60 seconds before expiry so a long call cannot start with a
        token that dies mid-flight.
        """
        now = dt.datetime.now(dt.UTC)
        if (
            not force
            and self._token is not None
            and self._expires_at is not None
            and now < self._expires_at - dt.timedelta(seconds=60)
        ):
            return self._token

        url = f"{LOGIN_BASE}/{self._credentials.tenant_id}/oauth2/v2.0/token"
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._credentials.client_id,
                        "client_secret": self._credentials.client_secret,
                        "scope": GRAPH_SCOPE,
                    },
                )
        except httpx.RequestError as exc:
            raise GraphError(
                f"Could not reach {LOGIN_BASE}: {type(exc).__name__}. "
                "Check outbound network access from this deployment."
            ) from None  # `from None`: the original may carry the request body

        if response.status_code != 200:
            raise GraphError(_describe_token_failure(response))

        body = response.json()
        self._token = body["access_token"]
        self._expires_at = now + dt.timedelta(seconds=int(body.get("expires_in", 3600)))
        return self._token

    # ─── Requests ────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        token = self.acquire_token()
        try:
            with httpx.Client(timeout=self._timeout) as client:
                return client.get(
                    f"{GRAPH_BASE}{path}",
                    params=params,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                )
        except httpx.RequestError as exc:
            raise GraphError(f"Could not reach Microsoft Graph: {type(exc).__name__}.") from None

    # ─── The two wizard verifications ────────────────────────────────────

    def test_token(self, required: Sequence[str] = ENTRA_PERMISSIONS_POLICY) -> TokenTest:
        """Acquire a token and report the tenant and the permissions granted.

        The wizard blocks on this: a deployment that looks configured but cannot
        authenticate is the worst outcome for this tool.

        ``required`` is the set that must appear in the token's ``roles`` claim,
        which differs by scoping mode — see the note on ENTRA_PERMISSIONS_RBAC.
        """
        try:
            token = self.acquire_token(force=True)
        except GraphError as exc:
            return TokenTest(ok=False, error=str(exc))

        granted = _decode_roles(token)
        missing = [p for p in required if p not in granted]

        tenant_domain = None
        try:
            tenant_domain = self.default_domain()
        except GraphError as exc:
            # Domain.Read.All may be absent, which `missing` already reports.
            log.info("graph_default_domain_unavailable", reason=type(exc).__name__)

        if missing:
            return TokenTest(
                ok=False,
                tenant_domain=tenant_domain,
                permissions=granted,
                missing_permissions=missing,
                error=(
                    f"Token acquired, but these application permissions are missing or "
                    f"not admin-consented: {', '.join(missing)}. "
                    f"Granted: {', '.join(granted) or 'none'}."
                ),
            )

        return TokenTest(ok=True, tenant_domain=tenant_domain, permissions=granted)

    def test_mailbox(self, mailbox: str) -> MailboxTest:
        """Prove the app can read the one mailbox, and report what is in it.

        This is also the check that proves scoping works end to end: it is the
        only mailbox the app should be able to open.
        """
        # Percent-encode: an address is operator-supplied and lands in a URL path.
        # `safe=""` also escapes "/", so nothing can climb out of /users/.
        target = quote(mailbox, safe="")
        try:
            folder = self._get(f"/users/{target}/mailFolders/inbox")
        except GraphError as exc:
            return MailboxTest(ok=False, error=str(exc))

        if folder.status_code == 404:
            return MailboxTest(
                ok=False,
                error=(
                    f"Graph returned 404 for {mailbox}. The mailbox does not exist, or the "
                    "app is scoped so that it cannot see it. Check the address first."
                ),
            )
        if folder.status_code in (401, 403):
            return MailboxTest(ok=False, error=f"{_describe_denial(folder)} {_RBAC_CACHE_HINT}")
        if folder.status_code != 200:
            return MailboxTest(ok=False, error=_describe_generic(folder))

        count = folder.json().get("totalItemCount")

        # Reading messages needs Mail.Read, which reading the folder does not. If
        # these fail the mailbox is reachable but unreadable, and reporting that
        # as a pass would let setup complete on a deployment that can never
        # ingest — exactly what the pinned constraint exists to prevent.
        try:
            oldest = self._edge_message(target, ascending=True)
            newest = self._edge_message(target, ascending=False)
        except GraphError as exc:
            return MailboxTest(
                ok=False,
                message_count=count,
                error=(
                    f"The mailbox exists and its folders are readable, but its messages "
                    f"are not: {exc} Reading report attachments needs Mail.Read. "
                    f"{_RBAC_CACHE_HINT}"
                ),
            )
        return MailboxTest(ok=True, message_count=count, oldest=oldest, newest=newest)

    def _edge_message(self, encoded_mailbox: str, ascending: bool) -> dt.datetime | None:
        """Timestamp of the oldest or newest message.

        Returns None only for a genuinely empty mailbox. Any non-200 raises:
        treating a 403 or a 429 as "empty" would silently downgrade a permission
        failure into a passing check with no reports in it.
        """
        order = "asc" if ascending else "desc"
        response = self._get(
            f"/users/{encoded_mailbox}/messages",
            params={
                "$top": 1,
                "$select": "receivedDateTime",
                "$orderby": f"receivedDateTime {order}",
            },
        )
        if response.status_code in (401, 403):
            raise GraphError(_describe_denial(response))
        if response.status_code != 200:
            raise GraphError(_describe_generic(response))

        items = response.json().get("value", [])
        if not items:
            return None
        raw = items[0].get("receivedDateTime")
        if not raw:
            return None
        return dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))

    # ─── Reading the report mailbox ──────────────────────────────────────

    def list_messages(
        self, mailbox: str, since: dt.datetime | None = None, page_size: int = 50
    ) -> Iterator[MailMessage]:
        """Yield messages oldest-first, following pagination.

        Oldest-first matters: ingestion checkpoints on the newest message it has
        processed, so a run interrupted halfway leaves a checkpoint that does not
        skip the messages it never reached.
        """
        target = quote(mailbox, safe="")
        params: dict[str, object] = {
            "$select": "id,subject,receivedDateTime,hasAttachments",
            "$orderby": "receivedDateTime asc",
            "$top": page_size,
        }
        if since is not None:
            # Graph wants a literal, not a quoted string, for datetime comparison.
            params["$filter"] = f"receivedDateTime gt {since.astimezone(dt.UTC):%Y-%m-%dT%H:%M:%SZ}"

        path: str | None = f"/users/{target}/messages"
        pages = 0
        while path is not None:
            response = self._get(path, params=params) if pages == 0 else self._get_absolute(path)
            if response.status_code in (401, 403):
                raise GraphError(_describe_denial(response))
            if response.status_code != 200:
                raise GraphError(_describe_generic(response))

            body = response.json()
            for item in body.get("value", []):
                received = item.get("receivedDateTime")
                yield MailMessage(
                    id=item["id"],
                    subject=item.get("subject") or "",
                    received=(
                        dt.datetime.fromisoformat(received.replace("Z", "+00:00"))
                        if received
                        else dt.datetime.now(dt.UTC)
                    ),
                    has_attachments=bool(item.get("hasAttachments")),
                )

            path = body.get("@odata.nextLink")
            pages += 1
            if pages > MAX_MESSAGE_PAGES:
                log.warning("graph_message_pagination_capped", pages=pages, mailbox=mailbox)
                return

    def get_attachments(self, mailbox: str, message_id: str) -> list[MailAttachment]:
        """Fetch a message's file attachments, decoded.

        Only ``fileAttachment`` is returned. An ``itemAttachment`` is an embedded
        message, which is the shape a forensic report takes — and forensic reports
        are discarded unparsed as a deliberate privacy position.
        """
        target = quote(mailbox, safe="")
        message = quote(message_id, safe="")
        response = self._get(f"/users/{target}/messages/{message}/attachments")
        if response.status_code in (401, 403):
            raise GraphError(_describe_denial(response))
        if response.status_code != 200:
            raise GraphError(_describe_generic(response))

        attachments: list[MailAttachment] = []
        for item in response.json().get("value", []):
            if item.get("@odata.type") != "#microsoft.graph.fileAttachment":
                continue
            raw = item.get("contentBytes")
            if not raw:
                continue
            try:
                content = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError):
                log.info("graph_attachment_not_base64", name=item.get("name"))
                continue
            attachments.append(
                MailAttachment(
                    name=item.get("name") or "attachment",
                    content_type=item.get("contentType") or "",
                    content=content,
                )
            )
        return attachments

    def _get_absolute(self, url: str) -> httpx.Response:
        """Follow an @odata.nextLink, which is a fully-qualified URL."""
        token = self.acquire_token()
        try:
            with httpx.Client(timeout=self._timeout) as client:
                return client.get(
                    url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
                )
        except httpx.RequestError as exc:
            raise GraphError(f"Could not reach Microsoft Graph: {type(exc).__name__}.") from None

    # ─── Domains ─────────────────────────────────────────────────────────

    def default_domain(self) -> str | None:
        """The tenant's default verified domain, for the wizard's Tenant fact."""
        response = self._get("/domains", params={"$select": "id,isDefault,isVerified"})
        if response.status_code != 200:
            raise GraphError(_describe_generic(response))
        domains = response.json().get("value", [])
        for domain in domains:
            if domain.get("isDefault"):
                return domain.get("id")
        return domains[0].get("id") if domains else None

    def verified_domains(self) -> list[str]:
        """Every verified domain in the tenant. Feeds the daily sync in M5."""
        response = self._get("/domains", params={"$select": "id,isVerified"})
        if response.status_code != 200:
            raise GraphError(_describe_generic(response))
        return [d["id"] for d in response.json().get("value", []) if d.get("isVerified")]


# ─── Error rendering ─────────────────────────────────────────────────────────
# Operator-facing text. None of these may echo the client secret, and the token
# endpoint helpfully includes the submitted client_id in its error body, so the
# raw body is never passed through verbatim.


def _describe_token_failure(response: httpx.Response) -> str:
    try:
        body = response.json()
        code = body.get("error", "unknown_error")
        description = (body.get("error_description") or "").split("\r\n")[0]
    except ValueError:
        return f"Token request failed with HTTP {response.status_code}."

    known = {
        "invalid_client": (
            "The client secret is wrong or has expired. Secrets expire on a schedule "
            "set in Entra; check the registration's Certificates & secrets page."
        ),
        "unauthorized_client": "The application is not authorised in this tenant.",
        "invalid_request": "The tenant ID or client ID is malformed.",
        "invalid_scope": "The application has no Microsoft Graph permissions assigned.",
    }
    hint = known.get(code)
    return f"{hint or description or code} (AAD error: {code})"


def _describe_denial(response: httpx.Response) -> str:
    if response.status_code == 401:
        return "Graph rejected the token (401). It may have expired mid-request; try again."
    return (
        "Graph denied access to that mailbox (403). Either the application permission "
        "was never admin-consented, or the scoping assignment does not include this mailbox."
    )


def _describe_generic(response: httpx.Response) -> str:
    try:
        error = response.json().get("error", {})
        return f"Graph returned {response.status_code}: {error.get('code', 'unknown')}."
    except ValueError:
        return f"Graph returned HTTP {response.status_code}."

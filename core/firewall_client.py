"""Low-level Sophos SFOS XML API client.

Handles two authentication modes automatically:
* Token mode     -- SFOS returns a ``Token`` attribute; subsequent requests use it.
* Per-request    -- SFOS 22 returns no token; ``<Login>`` is embedded in every
                    request so each call is self-authenticated.

No host-object or host-group logic exists here.  The only operations exposed
are getting a firewall rule and updating a firewall rule.
"""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
import copy
import requests
import urllib3

from .firewall_errors import firewall_exception_message

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.LoggerAdapter(logging.getLogger(__name__), {"technical": True})

# XML status codes returned by SFOS inside HTTP 200 responses
_SUCCESS_CODES: frozenset[str] = frozenset({"200"})
# 502 = "already exists" -- idempotent and acceptable
_TOLERATED_CODES: frozenset[str] = frozenset({"502"})


# Attributes SFOS adds to Get responses that must NOT be echoed back in a Set.
_READONLY_ATTRIBUTES: frozenset[str] = frozenset({"transactionid"})


_CREDENTIAL_TAGS: tuple[str, ...] = ("Username", "Password")
_CREDENTIAL_RE = re.compile(
    r"(<(?:" + "|".join(_CREDENTIAL_TAGS) + r")>).*?(</(?:" + "|".join(_CREDENTIAL_TAGS) + r")>)",
    re.DOTALL,
)


def _redact_credentials(xml_text: str) -> str:
    """Mask ``<Username>``/``<Password>`` element contents before logging.

    SFOS's per-request auth mode embeds ``<Login>`` (with the plaintext
    password) in *every* API call, not just ``authenticate()`` -- so this
    must run on every logged request body, not only the login call.
    """
    return _CREDENTIAL_RE.sub(r"\1***REDACTED***\2", xml_text)


def _strip_readonly_attributes(element: ET.Element) -> None:
    """Recursively remove read-only attributes (e.g. ``transactionid``).

    SFOS decorates every element in a ``Get`` response with a ``transactionid``
    attribute. Sending these back in a ``Set operation="update"`` can cause the
    firewall to accept the request (code 200) while silently discarding the
    changes, so they are removed in place before upload.
    """
    for attr in _READONLY_ATTRIBUTES:
        if attr in element.attrib:
            del element.attrib[attr]
    for child in element:
        _strip_readonly_attributes(child)


class FirewallAPIError(Exception):
    """Raised when the Sophos SFOS API signals a non-success XML status."""

    def __init__(
        self,
        message: str,
        code: str = "",
        response_text: str = "",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.response_text = _redact_credentials(response_text)


@dataclass
class SophosClient:
    """Thin XML API client for Sophos SFOS 22.

    Parameters
    ----------
    host:
        Management-plane IP or hostname.
    port:
        HTTPS port of the XML API (e.g. 4444 or 20792).
    username / password:
        Credentials for the API user.
    timeout:
        HTTP request timeout in seconds.
    """

    host: str
    port: int
    username: str
    password: str
    timeout: int = 30

    # Internal state -- not part of the public interface
    _token: Optional[str] = field(default=None, init=False, repr=False)
    _authenticated: bool = field(default=False, init=False, repr=False)
    _per_request: bool = field(default=False, init=False, repr=False)
    _last_response: str = field(default="", init=False, repr=False)

    # ──────────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────────

    @property
    def _base_url(self) -> str:
        return f"https://{self.host}:{self.port}/webconsole/APIController"

    def _build_request(self, payload: str) -> str:
        """Wrap *payload* in a signed ``<Request>`` element."""
        if self._token:
            return f'<Request APIVersion="2200.1" token="{self._token}">{payload}</Request>'
        if self._per_request:
            login = (
                "<Login>"
                f"<Username>{self.username}</Username>"
                f"<Password>{self.password}</Password>"
                "</Login>"
            )
            return f'<Request APIVersion="2200.1">{login}{payload}</Request>'
        # Pre-auth state: used only during authenticate()
        return f'<Request APIVersion="2200.1">{payload}</Request>'

    def _send(self, body: str, context: str = "") -> ET.Element:
        """POST *body* as ``reqxml`` form data and return the parsed XML root."""
        logger.debug("SFOS request [%s]: %s", context, _redact_credentials(body))
        resp = requests.post(
            self._base_url,
            data={"reqxml": body},
            verify=False,
            timeout=self.timeout,
        )
        self._last_response = resp.text
        logger.debug("SFOS response [%s]: %s", context, _redact_credentials(resp.text))
        resp.raise_for_status()
        try:
            return ET.fromstring(resp.text)
        except ET.ParseError as exc:
            raise FirewallAPIError(
                f"Malformed XML response during {context}: {exc}",
                response_text=resp.text,
            ) from exc

    def _check_write_status(self, root: ET.Element, context: str) -> None:
        """Raise FirewallAPIError for any non-success status code in *root*."""
        for status in root.findall(".//Status"):
            code = (status.get("code") or "").strip()
            if not code or code in _SUCCESS_CODES or code in _TOLERATED_CODES:
                continue
            msg = (status.text or f"code {code}").strip()
            logger.error(
                "SFOS write failure [%s]: code=%s msg=%s | %.800s",
                context, code, msg, _redact_credentials(self._last_response),
            )
            raise FirewallAPIError(
                f"SFOS API error during {context}: code={code}, {msg}",
                code=code,
                response_text=self._last_response,
            )

    def _ensure_auth(self) -> None:
        if not self._authenticated:
            self.authenticate()

    # ──────────────────────────────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Authenticate and detect the SFOS auth mode (token vs per-request).

        Raises
        ------
        FirewallAPIError
            If the firewall explicitly rejects the credentials.
        """
        login_xml = (
            "<Login>"
            f"<Username>{self.username}</Username>"
            f"<Password>{self.password}</Password>"
            "</Login>"
        )
        # Build directly -- _build_request would double-embed <Login>
        body = f'<Request APIVersion="2200.1">{login_xml}</Request>'
        root = self._send(body, "authenticate")

        status_text = (
            root.findtext(".//status") or root.findtext(".//Status") or ""
        ).lower()
        if any(w in status_text for w in ("unsuccessful", "failure", "invalid")):
            raise FirewallAPIError(
                f"Authentication failed: {status_text}",
                response_text=self._last_response,
            )

        token = root.get("Token") or root.findtext(".//Token")
        if token:
            self._token = token
            self._per_request = False
            logger.debug("SFOS authentication succeeded using a session token")
        else:
            self._token = None
            self._per_request = True
            logger.debug("SFOS authentication succeeded using per-request credentials")
        self._authenticated = True

    def create_ip_host(self, name: str, ip: str) -> None:
        """Create (or confirm already-existing) an IP Host object on SFOS.

        SFOS requires every ``<Network>`` reference in a firewall rule to be
        the NAME of an existing IP Host object — raw IPs are rejected (501).
        This creates the minimal one-IP host before the rule is updated.

        Parameters
        ----------
        name:
            SFOS object name, e.g. ``"blocked-69-5-169-189"``.
        ip:
            IPv4 address the host represents, e.g. ``"69.5.169.189"``.
        """
        self._ensure_auth()
        logger.info(
            "DEBUG create_ip_host called -- name=%r  ip=%r", name, ip
        )
        payload = (
            "<Set>"
            "<IPHost>"
            f"<Name>{name}</Name>"
            "<IPFamily>IPv4</IPFamily>"
            "<HostType>IP</HostType>"
            f"<IPAddress>{ip}</IPAddress>"
            "</IPHost>"
            "</Set>"
        )
        xml_body = self._build_request(payload)
        logger.info(
            "DEBUG create_ip_host request XML: %.500s", _redact_credentials(xml_body)
        )
        root = self._send(xml_body, f"create_ip_host({name!r}={ip!r})")
        logger.info(
            "DEBUG create_ip_host SFOS response: %.500s",
            _redact_credentials(self._last_response),
        )
        self._check_write_status(root, f"create_ip_host({name!r})")
        logger.debug("IP host %r (%s) confirmed on SFOS", name, ip)

    def ip_host_exists(self, name: str, ip: str = "") -> bool:
        """Return whether the named IP Host already exists on SFOS.

        When *ip* is supplied, the host must also contain that exact address.
        This read-before-create check keeps startup and live processing
        idempotent without relying solely on SFOS's tolerated 502 response.
        """
        self._ensure_auth()
        payload = f"<Get><IPHost><Name>{name}</Name></IPHost></Get>"
        root = self._send(
            self._build_request(payload),
            f"get_ip_host({name!r})",
        )
        for host in root.findall(".//IPHost"):
            found_name = (host.findtext("Name") or "").strip()
            found_ip = (host.findtext("IPAddress") or "").strip()
            if found_name == name and (not ip or found_ip == ip):
                return True
        return False

    def delete_ip_host(self, name: str) -> None:
        """Delete an IP Host object from SFOS.

        Best-effort from the caller's perspective: SFOS rejects deleting a
        host object that is still referenced by another rule, which surfaces
        here as a :class:`FirewallAPIError` like any other write failure --
        callers that only want "best effort cleanup, leave it if still in
        use elsewhere" semantics (see ``rule_updater.unblock_ip``) should
        catch that exception themselves rather than treating it as fatal.

        Parameters
        ----------
        name:
            SFOS object name, e.g. ``"blocked-69-5-169-189"``.
        """
        self._ensure_auth()
        payload = (
            "<Remove>"
            "<IPHost>"
            f"<Name>{name}</Name>"
            "</IPHost>"
            "</Remove>"
        )
        xml_body = self._build_request(payload)
        root = self._send(xml_body, f"delete_ip_host({name!r})")
        self._check_write_status(root, f"delete_ip_host({name!r})")
        logger.debug("IP host %r deleted from SFOS", name)

    def get_firewall_rule(self, rule_name: str) -> ET.Element:
        """Fetch the named firewall rule from SFOS.

        Returns
        -------
        ET.Element
            The root ``<Response>`` element of the SFOS reply (unparsed
            beyond the root -- caller can locate ``<FirewallRule>`` inside).
        """
        self._ensure_auth()
        payload = f"<Get><FirewallRule><Name>{rule_name}</Name></FirewallRule></Get>"
        logger.debug("Fetching firewall rule %r", rule_name)
        return self._send(
            self._build_request(payload),
            f"get_rule({rule_name!r})",
        )

    def set_firewall_rule(self, rule_element: ET.Element, rule_name: str) -> ET.Element:
        """Upload an updated *rule_element* to the firewall.

        The rule element originates from a ``Get`` response, which decorates
        every element with a read-only ``transactionid`` attribute.  Echoing
        those back in a ``Set`` request can make SFOS silently ignore the
        update, so they are stripped from a deep copy before upload.
        """
        self._ensure_auth()

        # Deep copy so we upload a clean, standalone rule element
        rule_copy = copy.deepcopy(rule_element)
        _strip_readonly_attributes(rule_copy)
        rule_xml = ET.tostring(rule_copy, encoding="unicode")
        payload = f'<Set operation="update">{rule_xml}</Set>'
        body = self._build_request(payload)
        logger.debug("Uploading updated rule %r to firewall", rule_name)
        logger.debug("Firewall rule update payload: %s", rule_xml)
        root = self._send(body, f"set_rule({rule_name!r})")
        self._check_write_status(root, f"set_rule({rule_name!r})")
        return root

    def logout(self) -> None:
        """Close the session (best-effort; ignores errors)."""
        if not self._authenticated:
            return
        try:
            body = self._build_request("<Logout/>")
            self._send(body, "logout")
        except Exception:
            pass
        self._token = None
        self._authenticated = False
        self._per_request = False
        logger.debug("SFOS session closed")

    @property
    def last_response(self) -> str:
        """Text of the most recent SFOS response, with credentials redacted.

        Safe to log directly -- callers (e.g. ``rule_updater``) do exactly
        that on failure.
        """
        return _redact_credentials(self._last_response)


def ping(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: int = 10,
) -> tuple[bool, str]:
    """Lightweight connectivity check -- authenticate and immediately log out.

    Returns ``(True, "")`` on success or ``(False, error_message)`` on any
    connection, authentication, or API failure. Never raises.
    """
    client = SophosClient(host=host, port=port, username=username, password=password, timeout=timeout)
    try:
        client.authenticate()
        return True, ""
    except FirewallAPIError as exc:
        logger.debug("Full firewall ping exception", exc_info=True)
        return False, firewall_exception_message(exc, timeout)
    except requests.RequestException as exc:
        logger.debug("Full firewall ping exception", exc_info=True)
        return False, firewall_exception_message(exc, timeout)
    except Exception as exc:  # pragma: no cover -- defensive catch-all
        logger.debug("Full firewall ping exception", exc_info=True)
        return False, firewall_exception_message(exc, timeout)
    finally:
        try:
            client.logout()
        except Exception:
            pass

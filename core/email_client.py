"""Provider-agnostic IMAP and SMTP transport.

All connection settings are read from :class:`~core.config.AppConfig`.
No provider-specific hostnames or ports are hardcoded here — change `.env`
to switch between Outlook, Gmail, or any other IMAP/SMTP provider.
"""
from __future__ import annotations

import imaplib
import logging
import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Optional

from .config import AppConfig
from . import email_status

logger = logging.LoggerAdapter(logging.getLogger(__name__), {"technical": True})

_DEFAULT_TIMEOUT = 30
class EmailConnectionError(Exception):
    """Raised when IMAP or SMTP connection/authentication fails."""


@dataclass(frozen=True)
class ImapFolderState:
    folder: str
    uidvalidity: str


def _last_imap_response_value(connection: object, name: str) -> str:
    """Read a numeric SELECT response without exposing protocol data."""
    values: object = None
    try:
        _typ, values = connection.response(name)  # type: ignore[attr-defined]
    except Exception:
        values = None
    if not values:
        try:
            values = connection.untagged_responses.get(name, [])  # type: ignore[attr-defined]
        except Exception:
            values = []
    if not isinstance(values, (list, tuple)):
        return ""
    for value in reversed(values):
        if isinstance(value, bytes):
            value = value.decode("ascii", errors="ignore")
        match = re.search(r"\d+", str(value))
        if match:
            return match.group(0)
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# IMAP
# ──────────────────────────────────────────────────────────────────────────────

class ImapMailbox:
    """Thin wrapper around imaplib for polling a configured mailbox."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._conn: Optional[imaplib.IMAP4 | imaplib.IMAP4_SSL] = None

    def connect(self) -> None:
        """Open an IMAP connection and authenticate."""
        cfg = self._config
        timeout = cfg.imap_timeout
        logger.info(
            "IMAP connecting to %s:%s (ssl=%s, mailbox=%s)",
            cfg.imap_host,
            cfg.imap_port,
            cfg.imap_use_ssl,
            cfg.imap_mailbox,
        )
        try:
            if cfg.imap_use_ssl:
                self._conn = imaplib.IMAP4_SSL(
                    cfg.imap_host, cfg.imap_port, timeout=timeout
                )
            else:
                self._conn = imaplib.IMAP4(
                    cfg.imap_host, cfg.imap_port, timeout=timeout
                )
                if cfg.imap_use_starttls:
                    self._conn.starttls(ssl_context=ssl.create_default_context())
            self._conn.login(cfg.email_username, cfg.email_password)
        except imaplib.IMAP4.error as exc:
            email_status.set_status("imap", False, str(exc))
            logger.error(
                "IMAP authentication failed for %s@%s:%s: %s",
                cfg.email_username, cfg.imap_host, cfg.imap_port, exc,
            )
            raise EmailConnectionError(
                f"IMAP authentication failed for {cfg.email_username}: {exc}"
            ) from exc
        except OSError as exc:
            email_status.set_status("imap", False, str(exc))
            logger.error(
                "IMAP connection failed to %s:%s: %s",
                cfg.imap_host, cfg.imap_port, exc,
            )
            raise EmailConnectionError(
                f"IMAP connection failed to {cfg.imap_host}:{cfg.imap_port}: {exc}"
            ) from exc
        logger.info(
            "IMAP authenticated successfully as %s on %s:%s",
            cfg.email_username, cfg.imap_host, cfg.imap_port,
        )
        email_status.set_status("imap", True, "Authentication and connection succeeded")

    def disconnect(self) -> None:
        """Close the IMAP session (best-effort)."""
        if self._conn is None:
            return
        for method in (self._conn.close, self._conn.logout):
            try:
                method()
            except Exception:
                pass
        self._conn = None
        logger.debug("IMAP session closed")

    def select_folder(self, folder: str) -> ImapFolderState:
        """Select *folder* read-only and return its UIDVALIDITY generation."""
        if self._conn is None:
            raise EmailConnectionError("IMAP not connected")
        typ, _ = self._conn.select(folder, readonly=True)
        if typ != "OK":
            raise EmailConnectionError(f"IMAP failed to select mailbox {folder!r}")
        uidvalidity = _last_imap_response_value(self._conn, "UIDVALIDITY")
        if not uidvalidity:
            raise EmailConnectionError(
                f"IMAP mailbox {folder!r} did not provide UIDVALIDITY"
            )
        logger.debug(
            "IMAP folder selected | folder=%r uidvalidity=%s",
            folder,
            uidvalidity,
        )
        return ImapFolderState(folder=folder, uidvalidity=uidvalidity)

    def search_uids_since(self, first_uid: int) -> list[str]:
        """Return all UIDs at or above *first_uid*, independent of flags."""
        if self._conn is None:
            raise EmailConnectionError("IMAP not connected")
        typ, data = self._conn.uid("SEARCH", None, "UID", f"{max(1, first_uid)}:*")
        logger.debug(
            "IMAP UID search response | first_uid=%d type=%s data=%r",
            first_uid,
            typ,
            data,
        )
        if typ != "OK":
            raise EmailConnectionError("IMAP UID search failed")
        if not data or not data[0]:
            return []
        uids = [
            value.decode("ascii") if isinstance(value, bytes) else str(value)
            for value in data[0].split()
        ]
        return sorted((uid for uid in uids if uid.isdigit()), key=int)

    def fetch_message_peek(self, uid: str) -> bytes:
        """Fetch one full message without changing its ``\\Seen`` flag."""
        if self._conn is None:
            raise EmailConnectionError("IMAP not connected")
        typ, msg_data = self._conn.uid("FETCH", uid, "(BODY.PEEK[])")
        logger.debug("IMAP BODY.PEEK fetch | uid=%s type=%s", uid, typ)
        if typ != "OK":
            raise EmailConnectionError(f"IMAP failed to fetch UID {uid}")
        for part in msg_data or []:
            if isinstance(part, tuple) and len(part) >= 2 and isinstance(part[1], bytes):
                return part[1]
        raise EmailConnectionError(f"IMAP returned no message body for UID {uid}")

    def fetch_unread(self) -> list[tuple[str, bytes]]:
        """Return ``(uid, raw_bytes)`` tuples for unread messages."""
        if self._conn is None:
            raise EmailConnectionError("IMAP not connected")
        mailbox = self._config.imap_mailbox

        typ, sel_data = self._conn.select(mailbox, readonly=False)
        if typ != "OK":
            raise EmailConnectionError(f"IMAP failed to select mailbox {mailbox!r}")

        # Log mailbox counters so we can see EXISTS / RECENT / UNSEEN immediately.
        exists = self._conn.untagged_responses.get("EXISTS", [b"?"])
        recent = self._conn.untagged_responses.get("RECENT", [b"?"])
        unseen_info = self._conn.untagged_responses.get("UNSEEN", [b"?"])
        logger.info(
            "IMAP: selected %r -- EXISTS=%s RECENT=%s UNSEEN=%s",
            mailbox,
            exists[-1] if exists else "?",
            recent[-1] if recent else "?",
            unseen_info[-1] if unseen_info else "?",
        )

        typ, data = self._conn.uid("SEARCH", "UNSEEN")
        logger.debug("IMAP SEARCH UNSEEN response: typ=%s data=%r", typ, data)

        if typ != "OK":
            logger.warning("IMAP: SEARCH UNSEEN returned non-OK status: %s", typ)
            return []

        if not data or not data[0]:
            logger.debug("IMAP: no unread messages in %s", mailbox)
            return []

        uid_list = data[0].split()
        logger.info(
            "IMAP: SEARCH UNSEEN returned %d UID(s): %s",
            len(uid_list),
            b" ".join(uid_list).decode(),
        )

        results: list[tuple[str, bytes]] = []
        for uid_bytes in uid_list:
            uid = uid_bytes.decode() if isinstance(uid_bytes, bytes) else str(uid_bytes)
            typ2, msg_data = self._conn.uid("FETCH", uid, "(RFC822)")
            if typ2 != "OK":
                logger.warning("IMAP: failed to fetch uid=%s", uid)
                continue
            for part in msg_data:
                if isinstance(part, tuple) and len(part) >= 2:
                    results.append((uid, part[1]))
                    break
        logger.debug("IMAP: fetched %d unread message(s) from %s", len(results), mailbox)
        return results

    def mark_seen(self, uid: str) -> None:
        """Mark a message as read."""
        if self._conn is None:
            return
        try:
            self._conn.uid("STORE", uid, "+FLAGS", "(\\Seen)")
            logger.debug("IMAP: marked uid=%s as seen", uid)
        except Exception as exc:
            logger.warning("IMAP: failed to mark uid=%s as seen: %s", uid, exc)


# ──────────────────────────────────────────────────────────────────────────────
# SMTP
# ──────────────────────────────────────────────────────────────────────────────

def _open_smtp_connection(config: AppConfig) -> smtplib.SMTP | smtplib.SMTP_SSL:
    """Open an SMTP connection using SSL or STARTTLS per ``config``.

    * ``SMTP_USE_SSL=true``  -> ``smtplib.SMTP_SSL()`` (no ``starttls()``)
    * ``SMTP_USE_TLS=true``  -> plain ``smtplib.SMTP()`` + ``starttls()``
    * both false             -> plain ``smtplib.SMTP()`` without encryption
    """
    ssl_context = ssl.create_default_context()

    if config.smtp_use_ssl:
        logger.info(
            "SMTP using implicit SSL (SMTP_SSL) on %s:%s",
            config.smtp_host, config.smtp_port,
        )
        return smtplib.SMTP_SSL(
            config.smtp_host,
            config.smtp_port,
            timeout=config.smtp_timeout,
            context=ssl_context,
        )

    logger.info(
        "SMTP using plain connection on %s:%s (starttls=%s)",
        config.smtp_host, config.smtp_port, config.smtp_use_tls,
    )
    smtp = smtplib.SMTP(
        config.smtp_host,
        config.smtp_port,
        timeout=config.smtp_timeout,
    )
    if config.smtp_use_tls:
        smtp.starttls(context=ssl_context)
        logger.debug("SMTP STARTTLS negotiated with %s:%s", config.smtp_host, config.smtp_port)
    return smtp


def send_notification(
    config: AppConfig,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
) -> None:
    """Send one notification email to ``config.notification_email``.

    The application sends a single message to the configured distribution or
    shared mailbox address. Recipient forwarding is handled by IT/mail rules —
    this code does not manage multiple recipients.

    ``body`` is always sent as the plain-text part. When ``html_body`` is
    given, it is attached as the ``text/html`` alternative so HTML-capable
    clients render the styled version while others fall back to plain text.

    Raises
    ------
    EmailConnectionError
        On SMTP connection or authentication failure.
    """
    to_addr = config.notification_email
    from_addr = config.smtp_from_address

    if not to_addr:
        logger.warning("SMTP: NOTIFICATION_EMAIL is empty -- skipping notification")
        return

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    logger.info(
        "SMTP connecting to %s:%s (tls=%s, ssl=%s) to send notification",
        config.smtp_host,
        config.smtp_port,
        config.smtp_use_tls,
        config.smtp_use_ssl,
    )
    logger.info(
        "SMTP notification: from=%r to=%r subject=%r",
        from_addr, to_addr, subject,
    )

    try:
        with _open_smtp_connection(config) as smtp:
            _smtp_login_and_send(smtp, config, msg, to_addr)
    except smtplib.SMTPAuthenticationError as exc:
        email_status.set_status("smtp", False, str(exc))
        logger.error(
            "SMTP authentication failed for %s@%s:%s: %s",
            config.smtp_username, config.smtp_host, config.smtp_port, exc,
        )
        raise EmailConnectionError(
            f"SMTP authentication failed for {config.smtp_username}: {exc}"
        ) from exc
    except OSError as exc:
        email_status.set_status("smtp", False, str(exc))
        logger.error(
            "SMTP connection failed to %s:%s: %s",
            config.smtp_host, config.smtp_port, exc,
        )
        raise EmailConnectionError(
            f"SMTP connection failed to {config.smtp_host}:{config.smtp_port}: {exc}"
        ) from exc
    except smtplib.SMTPException as exc:
        email_status.set_status("smtp", False, str(exc))
        logger.error("SMTP send failed to %s: %s", to_addr, exc)
        raise EmailConnectionError(f"SMTP send failed: {exc}") from exc

    logger.debug("SMTP notification delivered")
    email_status.set_status("smtp", True, "Authentication and delivery succeeded")


def check_smtp_connection(config: AppConfig) -> None:
    """Connect and authenticate to SMTP without sending a message."""
    logger.info(
        "SMTP connectivity test to %s:%s (tls=%s, ssl=%s)",
        config.smtp_host, config.smtp_port, config.smtp_use_tls, config.smtp_use_ssl,
    )
    try:
        with _open_smtp_connection(config) as smtp:
            if config.smtp_username and config.smtp_password:
                smtp.login(config.smtp_username, config.smtp_password)
            smtp.noop()
    except smtplib.SMTPAuthenticationError as exc:
        email_status.set_status("smtp", False, str(exc))
        raise EmailConnectionError(
            f"SMTP authentication failed for {config.smtp_username}: {exc}"
        ) from exc
    except (OSError, smtplib.SMTPException) as exc:
        email_status.set_status("smtp", False, str(exc))
        raise EmailConnectionError(
            f"SMTP connection failed to {config.smtp_host}:{config.smtp_port}: {exc}"
        ) from exc
    email_status.set_status("smtp", True, "Authentication and connection succeeded")


def _smtp_login_and_send(
    smtp: smtplib.SMTP | smtplib.SMTP_SSL,
    config: AppConfig,
    msg: EmailMessage,
    to_addr: str,
) -> None:
    """Authenticate (if credentials provided) and send *msg*."""
    if config.smtp_username and config.smtp_password:
        smtp.login(config.smtp_username, config.smtp_password)
        logger.debug("SMTP authenticated")
    else:
        logger.warning("SMTP: no credentials configured -- sending without AUTH")
    smtp.send_message(msg)
    logger.debug("SMTP message accepted by %s:%s for recipient %s",
                config.smtp_host, config.smtp_port, to_addr)

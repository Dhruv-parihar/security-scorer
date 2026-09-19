"""
Authorization Precondition Module (R4 Fix — Phase 2)
=====================================================
Active scanning (network or web) requires an explicit authorization
record in the research database before proceeding.

Rules:
- Authorization is NEVER inferred from an IP address or URL alone.
- Authorization is NEVER granted automatically.
- If no matching record exists, scanning is BLOCKED with a clear error.
- The authorization check is non-invasive: it only reads from the DB.
- Passive analysis (OS hardening on localhost) does not require a
  network-target authorization record.

Usage:
    from modules.authorization import require_authorization, AuthorizationError
    try:
        target_id = require_authorization(conn, target_ip_or_url)
    except AuthorizationError as e:
        # block the scan, show error to user
        print(f"BLOCKED: {e}")
"""


class AuthorizationError(Exception):
    """Raised when active scanning is attempted without authorization."""
    pass


def require_authorization(conn, identifier, scope=None):
    """
    Verify that an explicit authorization record exists for this identifier.

    identifier: the target IP, hostname, or URL (used as target_alias lookup)
    scope:      optional scope filter (e.g. "NETWORK", "WEB", "ALL")
    conn:       open DB connection (from db.schema.get_connection)

    Returns: target_id string if authorized.
    Raises:  AuthorizationError if not authorized or record not found.

    The lookup matches target_alias exactly (case-insensitive).
    Authorization_status must be one of:
        OWNED, LAB, EXPLICITLY_AUTHORIZED, CONSENTED_RESEARCH
    """
    if not identifier or not str(identifier).strip():
        raise AuthorizationError(
            "Scanning blocked: no target identifier provided."
        )

    identifier = str(identifier).strip()

    row = conn.execute(
        """
        SELECT target_id, target_alias, authorization_status, authorization_ref
        FROM target
        WHERE LOWER(target_alias) = LOWER(?)
        """,
        (identifier,)
    ).fetchone()

    if row is None:
        raise AuthorizationError(
            f"Scanning blocked: no authorization record found for '{identifier}'. "
            f"Create a target record in the research database with an explicit "
            f"authorization_status (OWNED, LAB, EXPLICITLY_AUTHORIZED, or "
            f"CONSENTED_RESEARCH) before scanning this target."
        )

    valid_statuses = ("OWNED", "LAB", "EXPLICITLY_AUTHORIZED", "CONSENTED_RESEARCH")
    if row["authorization_status"] not in valid_statuses:
        raise AuthorizationError(
            f"Scanning blocked: target '{identifier}' has authorization_status "
            f"'{row['authorization_status']}' which is not a valid active-scan "
            f"authorization. Valid statuses: {', '.join(valid_statuses)}."
        )

    return row["target_id"]


def check_authorization(conn, identifier):
    """
    Non-raising version. Returns (authorized: bool, target_id_or_None, message).
    Useful for Flask form validation before attempting a scan.
    """
    try:
        target_id = require_authorization(conn, identifier)
        return True, target_id, "Authorized"
    except AuthorizationError as e:
        return False, None, str(e)

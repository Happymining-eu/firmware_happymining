"""Operator command line.

python -m happymining.cli check-config
python -m happymining.cli migrate
python -m happymining.cli create-admin you@example.com
python -m happymining.cli enroll-mfa you@example.com
python -m happymining.cli seed-demo
python -m happymining.cli verify
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from sqlalchemy import select

from .audit import Actor, verify_chain
from .config import ConfigError, get_settings
from .db import session_scope
from .migrate import upgrade
from .models import User
from .security import decrypt_text, totp_uri
from .services import accounts
from .services.ledger import verify_ledger
from .services.system import ensure_database_mode


def _password() -> str:
    first = getpass.getpass("Password (12+ characters): ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("passwords do not match")
    return first


def cmd_check_config(_: argparse.Namespace) -> int:
    settings = get_settings()
    problems = settings.problems()
    print(
        f"mode: {settings.mode}   provider: {settings.provider}   payout provider: {settings.payout_provider}"
    )
    if problems:
        print("NOT OK:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("configuration is acceptable for this mode")
    return 0


def cmd_migrate(_: argparse.Namespace) -> int:
    settings = get_settings()
    upgrade(settings.database_url)
    print("database is at the latest revision")
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    settings = get_settings()
    settings.validate_for_startup()
    ensure_database_mode(settings)
    password = _password()
    with session_scope() as db:
        user = accounts.create_user(
            db,
            Actor.system("cli"),
            email=args.email,
            role="admin",
            display_name=args.name or "",
            password=password,
        )
        uri = accounts.begin_mfa_enrollment(db, settings, user)
        print(f"created admin {user.email}")
        print("Add this account to an authenticator app, then run: enroll-mfa", user.email)
        print(uri)
    return 0


def cmd_enroll_mfa(args: argparse.Namespace) -> int:
    settings = get_settings()
    ensure_database_mode(settings)
    with session_scope() as db:
        user = db.execute(
            select(User).where(User.email == accounts.normalise_email(args.email))
        ).scalar_one_or_none()
        if user is None:
            raise SystemExit("no such user")
        if not user.totp_secret_enc:
            print(accounts.begin_mfa_enrollment(db, settings, user))
        elif not user.mfa_enabled:
            print(totp_uri(decrypt_text(settings, user.totp_secret_enc), user.email))
        code = input("Current 6-digit code from the authenticator app: ")
        accounts.activate_mfa(db, settings, Actor.system("cli"), user, code)
        print("MFA is active for", user.email)
    return 0


def cmd_seed_demo(_: argparse.Namespace) -> int:
    from .demo.seed import seed_demo

    settings = get_settings()
    settings.validate_for_startup()
    ensure_database_mode(settings)
    with session_scope() as db:
        print(json.dumps(seed_demo(db, settings), indent=2))
    return 0


def _user(db, email: str) -> User:
    user = db.execute(select(User).where(User.email == accounts.normalise_email(email))).scalar_one_or_none()
    if user is None:
        raise SystemExit("no such user")
    return user


def cmd_deactivate_user(args: argparse.Namespace) -> int:
    ensure_database_mode(get_settings())
    with session_scope() as db:
        user = accounts.deactivate_user(db, Actor.system("cli"), _user(db, args.email).id)
        print(f"{user.email} is deactivated and its sessions are revoked")
    return 0


def cmd_set_password(args: argparse.Namespace) -> int:
    ensure_database_mode(get_settings())
    password = _password()
    with session_scope() as db:
        user = _user(db, args.email)
        accounts.set_password(db, Actor.system("cli"), user, password)
        print(f"password replaced for {user.email}; its sessions are revoked")
    return 0


RUNTIME_ROLE_ENV = "HM_DB_APP_PASSWORD"
# Tables the runtime role may only add to and read. The journal, its accounts
# and the audit trail are append-only for the application as well.
APPEND_ONLY_TABLES = ("journal_entries", "journal_lines", "audit_log", "ledger_accounts")


def cmd_setup_runtime_role(args: argparse.Namespace) -> int:
    """Create or update the unprivileged role the API and worker connect as.

    Run with the owner (migration) credentials in HM_DATABASE_URL. The runtime
    role is not a superuser and does not own the tables, so it cannot disable
    triggers. It gets no UPDATE, DELETE or TRUNCATE on the journal or the audit
    trail, and no direct write access to the balance cache.
    """
    import os
    import re

    from sqlalchemy import create_engine, text

    role = args.role
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("role name must be lower-case letters, digits and underscores")
    password = os.environ.get(RUNTIME_ROLE_ENV, "")
    if len(password) < 12:
        raise SystemExit(f"set {RUNTIME_ROLE_ENV} to a password of at least 12 characters")
    engine = create_engine(get_settings().database_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        database = conn.execute(text("SELECT current_database()")).scalar_one()
        exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).first()
        verb = "ALTER" if exists else "CREATE"
        # Role names and passwords cannot be bound parameters in DDL: the name
        # is validated above and the password is quoted by the server function.
        quoted = conn.execute(text("SELECT quote_literal(:p)"), {"p": password}).scalar_one()
        conn.execute(
            text(
                f"{verb} ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD {quoted}"
            )
        )
        statements = [
            f'GRANT CONNECT ON DATABASE "{database}" TO {role}',
            f"GRANT USAGE ON SCHEMA public TO {role}",
            f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}",
            f"REVOKE UPDATE, DELETE, TRUNCATE ON {', '.join(APPEND_ONLY_TABLES)} FROM {role}",
            # Written only by the SECURITY DEFINER journal trigger.
            f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ledger_balances FROM {role}",
            f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM {role}",
        ]
        for statement in statements:
            conn.execute(text(statement))
    engine.dispose()
    print(
        f"runtime role {role} is ready on database {database} (no superuser, journal and audit append-only)"
    )
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    ensure_database_mode(get_settings())
    with session_scope() as db:
        ledger = verify_ledger(db)
        audit_chain = verify_chain(db)
    print(json.dumps({"ledger": ledger, "audit_chain": audit_chain}, indent=2))
    return 0 if ledger["ok"] and audit_chain["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="happymining")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-config", help="validate the configuration for the selected mode").set_defaults(
        fn=cmd_check_config
    )
    sub.add_parser("migrate", help="apply database migrations").set_defaults(fn=cmd_migrate)
    admin = sub.add_parser("create-admin", help="create an admin and start MFA enrollment")
    admin.add_argument("email")
    admin.add_argument("--name", default="")
    admin.set_defaults(fn=cmd_create_admin)
    mfa = sub.add_parser("enroll-mfa", help="activate TOTP for a user")
    mfa.add_argument("email")
    mfa.set_defaults(fn=cmd_enroll_mfa)
    sub.add_parser("seed-demo", help="create synthetic demo data (DEMO mode only)").set_defaults(
        fn=cmd_seed_demo
    )
    off = sub.add_parser("deactivate-user", help="disable an account and revoke its sessions")
    off.add_argument("email")
    off.set_defaults(fn=cmd_deactivate_user)
    pw = sub.add_parser("set-password", help="replace a user's password and revoke their sessions")
    pw.add_argument("email")
    pw.set_defaults(fn=cmd_set_password)
    role = sub.add_parser(
        "setup-runtime-role", help=f"create the unprivileged database role (password from {RUNTIME_ROLE_ENV})"
    )
    role.add_argument("--role", default="happymining_app")
    role.set_defaults(fn=cmd_setup_runtime_role)
    sub.add_parser("verify", help="verify the ledger and the audit chain").set_defaults(fn=cmd_verify)
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

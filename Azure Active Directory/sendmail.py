#!/usr/bin/env python3
"""Send an authorized email through Microsoft Graph using app-only authentication.

The client secret is read from the ENTRA_CLIENT_SECRET environment variable and is
never stored in this source file. The Entra application requires Microsoft Graph
Mail.Send application permission with administrator consent. Exchange Online App
RBAC should be used to restrict the application to approved sender mailboxes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib.parse import quote

import requests

TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
SEND_MAIL_ENDPOINT = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send an authorized email through Microsoft Graph."
    )
    parser.add_argument("--tenant-id", required=True, help="Microsoft Entra tenant ID.")
    parser.add_argument("--client-id", required=True, help="Application client ID.")
    parser.add_argument("--sender", required=True, help="Authorized sender UPN or user ID.")
    parser.add_argument("--recipient", required=True, help="Recipient email address.")
    parser.add_argument("--subject", required=True, help="Email subject.")
    parser.add_argument("--body", required=True, help="Plain-text email body.")
    parser.add_argument(
        "--no-save-to-sent-items",
        action="store_true",
        help="Do not save the message in the sender's Sent Items folder.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print a redacted request summary without authenticating or sending.",
    )
    parser.add_argument(
        "--acknowledge-authorized-mailbox",
        action="store_true",
        required=True,
        help="Confirm that the application is authorized to send from the selected mailbox.",
    )
    return parser.parse_args()


def require_client_secret() -> str:
    secret = os.getenv("ENTRA_CLIENT_SECRET")
    if not secret:
        raise RuntimeError(
            "ENTRA_CLIENT_SECRET is not set. Store the app secret in the environment, "
            "not in the script or command history."
        )
    return secret


def get_access_token(
    session: requests.Session,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> str:
    response = session.post(
        TOKEN_ENDPOINT.format(tenant_id=quote(tenant_id, safe="")),
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": GRAPH_SCOPE,
        },
        timeout=30,
    )

    if not response.ok:
        raise RuntimeError(format_graph_error("Token request failed", response))

    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Token response did not contain an access_token.")
    return str(token)


def build_message(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "message": {
            "subject": args.subject,
            "body": {"contentType": "Text", "content": args.body},
            "toRecipients": [
                {"emailAddress": {"address": args.recipient}}
            ],
        },
        "saveToSentItems": not args.no_save_to_sent_items,
    }


def send_message(
    session: requests.Session,
    access_token: str,
    sender: str,
    message: dict[str, Any],
) -> None:
    response = session.post(
        SEND_MAIL_ENDPOINT.format(sender=quote(sender, safe="")),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=message,
        timeout=30,
    )

    if response.status_code != 202:
        raise RuntimeError(format_graph_error("Send-mail request failed", response))


def format_graph_error(prefix: str, response: requests.Response) -> str:
    request_id = response.headers.get("request-id") or response.headers.get("client-request-id")
    try:
        payload = response.json()
        error = payload.get("error", payload)
        code = error.get("code") if isinstance(error, dict) else None
        message = error.get("message") if isinstance(error, dict) else json.dumps(payload)
    except (ValueError, TypeError):
        code = None
        message = response.text.strip() or "No response body"

    details = [prefix, f"HTTP {response.status_code}"]
    if code:
        details.append(f"code={code}")
    if request_id:
        details.append(f"request-id={request_id}")
    details.append(f"message={message}")
    return " | ".join(details)


def main() -> int:
    args = parse_arguments()
    message = build_message(args)

    if args.dry_run:
        summary = {
            "tenant_id": args.tenant_id,
            "client_id": args.client_id,
            "sender": args.sender,
            "recipient": args.recipient,
            "subject": args.subject,
            "save_to_sent_items": not args.no_save_to_sent_items,
            "body_length": len(args.body),
        }
        print(json.dumps(summary, indent=2))
        print("Dry run complete. No authentication was attempted and no email was sent.")
        return 0

    client_secret = require_client_secret()

    with requests.Session() as session:
        access_token = get_access_token(
            session=session,
            tenant_id=args.tenant_id,
            client_id=args.client_id,
            client_secret=client_secret,
        )
        send_message(
            session=session,
            access_token=access_token,
            sender=args.sender,
            message=message,
        )

    print("Microsoft Graph accepted the message (HTTP 202). Delivery is not guaranteed by this response.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (requests.RequestException, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)

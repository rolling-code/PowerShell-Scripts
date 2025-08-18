import requests
import json

# Replace these values with your own
tenant_id = "xx"
client_id = "xx"
client_secret = "xx"
from_user = "mcontestabile@xx"  # Sender's email
to_user = "mcontestabile@xx"     # Recipient's email

# Get an access token
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
token_data = {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": "https://graph.microsoft.com/.default"
}
token_response = requests.post(token_url, data=token_data)
access_token = token_response.json().get("access_token")

if not access_token:
    print("Failed to obtain access token.")
    exit(1)

# Send an email using Microsoft Graph API
graph_url = f"https://graph.microsoft.com/v1.0/users/{from_user}/sendMail"
email_body = {
    "message": {
        "subject": "Test Email from Service Principal",
        "body": {
            "contentType": "Text",
            "content": "This is a test email sent by a service principal."
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": to_user
                }
            }
        ]
    }
}

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

response = requests.post(graph_url, headers=headers, json=email_body)

if response.status_code == 202:
    print("Email sent successfully!")
else:
    print(f"Failed to send email. Status code: {response.status_code}")
    print(response.json())

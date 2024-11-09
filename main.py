import os
import json
import base64
import re
import requests
import pandas as pd
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from textwrap import dedent
from openai import OpenAI

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Define a file path to store the last email ID processed
LAST_EMAIL_ID_FILE = "last_email_id.json"

# Load environment variables from .env
load_dotenv()

# OpenAI API key
openai_api_key = os.getenv("OPENAI_API_KEY")

# Create OpenAI client
client = OpenAI(api_key=openai_api_key)

# Model to use
MODEL = "gpt-4o-mini"  # Adjusted to match your specified model

# ntfy topic URL
NTFY_TOPIC_URL = "https://ntfy.sh/hz-mail-buddy"

def clean_text(text):
    text = re.sub(r'http\S+|www\.\S+', '', text)
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\b(unsubscribe|click here|preferences|privacy)\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    return text.strip()

def get_email_content(payload):
    import base64
    from bs4 import BeautifulSoup

    def traverse_parts(parts):
        for part in parts:
            mime_type = part.get('mimeType', '')
            if mime_type == 'text/plain':
                data = part['body'].get('data', '')
                if data:
                    text_content = base64.urlsafe_b64decode(data).decode('utf-8')
                    return clean_text(text_content)
            elif mime_type == 'text/html':
                data = part['body'].get('data', '')
                if data:
                    html_content = base64.urlsafe_b64decode(data).decode('utf-8')
                    text_content = BeautifulSoup(html_content, "html.parser").get_text()
                    return clean_text(text_content)
            elif 'parts' in part:
                # Recursively traverse nested parts
                result = traverse_parts(part['parts'])
                if result:
                    return result
        return None

    # Start traversal from the payload
    if 'parts' in payload:
        content = traverse_parts(payload['parts'])
        if content:
            return content
    elif payload.get('mimeType', '') == 'text/plain':
        data = payload['body'].get('data', '')
        if data:
            text_content = base64.urlsafe_b64decode(data).decode('utf-8')
            return clean_text(text_content)
    elif payload.get('mimeType', '') == 'text/html':
        data = payload['body'].get('data', '')
        if data:
            html_content = base64.urlsafe_b64decode(data).decode('utf-8')
            text_content = BeautifulSoup(html_content, "html.parser").get_text()
            return clean_text(text_content)

    return "No content available"

def get_email_category(message):
    if 'labelIds' in message:
        labels = message['labelIds']
        if 'CATEGORY_PROMOTIONS' in labels:
            return 'Promotions'
        elif 'CATEGORY_SOCIAL' in labels:
            return 'Social'
        elif 'CATEGORY_PERSONAL' in labels:
            return 'Primary'
    return 'Unknown'

def get_new_emails(service):
    # Fetch emails from the inbox received in the past 3 hours
    query = "is:inbox newer_than:1h"
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])

    email_data = []

    for msg in messages:
        email_id = msg['id']
        message = service.users().messages().get(userId='me', id=email_id, format='full').execute()
        headers = message['payload']['headers']
        date = next((h['value'] for h in headers if h['name'] == 'Date'), "No Date")
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")

        # Determine category based on labels
        category = get_email_category(message)

        # Skip emails in the promotions category
        if category == 'Promotions':
            continue

        # Get the email content
        email_content = get_email_content(message['payload'])

        # Append data to list
        email_data.append({
            "Date Received": date,
            "Sender": sender,
            "Category": category,
            "Message Content": email_content,
            "Subject": subject,
            "Email ID": email_id
        })

    # Create DataFrame
    df = pd.DataFrame(email_data)
    return df

    last_email_id = load_last_email_id()
    query = "is:inbox"
    # If it's the first run, fetch only the latest unread email
    if not last_email_id:
        query += " is:unread"
        max_results = 1
    else:
        # Fetch all emails after the last email ID
        query += f" newer_than_id:{last_email_id}"
        max_results = None  # No limit

    # Fetch messages matching the query
    results = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
    messages = results.get('messages', [])

    email_data = []
    last_processed_email_id = last_email_id

    for msg in reversed(messages):  # Reverse to process oldest first
        email_id = msg['id']
        message = service.users().messages().get(userId='me', id=email_id, format='full').execute()
        headers = message['payload']['headers']
        date = next((h['value'] for h in headers if h['name'] == 'Date'), "No Date")
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")

        # Determine category based on labels
        category = get_email_category(message)

        # Skip emails in the promotions category
        if category == 'Promotions':
            continue

        # Get the email content
        email_content = get_email_content(message['payload'])

        # Append data to list
        email_data.append({
            "Date Received": date,
            "Sender": sender,
            "Category": category,
            "Message Content": email_content,
            "Subject": subject,
            "Email ID": email_id
        })

        # Update the last processed email ID
        last_processed_email_id = email_id

    # Save the ID of the last processed email
    if last_processed_email_id:
        save_last_email_id(last_processed_email_id)

    # Create DataFrame
    df = pd.DataFrame(email_data)
    return df

def parse_email(email_content):
    email_parser_prompt = '''
    You are an email parser. Your task is to assess whether an email seems important and provide a 15-word max summary of its contents.
    Label the email as "Important" or "Not Important" based on keywords like deadlines, meetings, urgent tasks, approvals, or action items.
    Then, summarize the key details and main point of the email in a short sentence eg: Hugo wants to have lunch tomorrow. the mail always includes contact details so don't mention that.
    '''
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": dedent(email_parser_prompt)
            },
            {
                "role": "user",
                "content": email_content
            }
        ],
        # Keep the OpenAI API call intact as per your latest schema
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "email_parsing",
                "schema": {
                    "type": "object",
                    "properties": {
                        "importance": {"type": "string", "enum": ["Important", "Not Important"]},
                        "summary": {"type": "string"}
                    },
                    "required": ["importance", "summary"],
                    "additionalProperties": False
                },
                "strict": True
            }
        }
    )

    # Extract the content and parse it into a dictionary
    message_content = response.choices[0].message.content

    # Check if message_content is a string; if so, parse it as JSON
    if isinstance(message_content, str):
        try:
            result = json.loads(message_content)
        except json.JSONDecodeError:
            print("Error: Assistant's reply is not valid JSON.")
            result = {"importance": "Unknown", "summary": message_content}
    elif isinstance(message_content, dict):
        result = message_content
    else:
        # Handle unexpected types
        print("Error: Unexpected response type from OpenAI API.")
        result = {}

    return result

def remove_non_ascii(s):
    return ''.join(c if ord(c) < 256 else '?' for c in s)

def send_notification(message_content, sender, subject):
    try:
        importance = message_content.get("importance", "Not Important")
        summary = message_content.get("summary", "")
    except AttributeError:
        # Handle cases where message_content is not a dict
        print("Error: message_content is not a dictionary.")
        return

    # Determine priority and urgency label
    if importance == "Important":
        priority = "urgent"
        urgency_label = "Urgent"
    else:
        priority = "low"
        urgency_label = "Not Urgent"

    # Extract sender name without email address
    # sender may be in the format 'Name <email@example.com>'
    import email.utils
    name, email_address = email.utils.parseaddr(sender)
    if name == '':
        # If name is empty, use the email username (before '@')
        name = email_address.split('@')[0]

    # Create the notification title
    notification_title = f"{urgency_label}: from {name}"

    # Normalize notification_title to ASCII
    notification_title = remove_non_ascii(notification_title)

    # Notification body is the summary
    notification_body = summary

    # Send POST request to ntfy
    response = requests.post(
        NTFY_TOPIC_URL,
        data=notification_body.encode('utf-8'),
        headers={
            "Title": notification_title,
            "Priority": priority,
            "Tags": "email,summary",
            "Markdown": "yes"  # Optional if Markdown formatting is desired
        }
    )
    return response

def main():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists("credentials.json"):
                print("Missing credentials.json file.")
                return
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)

        # Fetch new emails
        df = get_new_emails(service)

        if df.empty:
            print("No new emails.")
            return

        # Process each new email
        for index, row in df.iterrows():
            email_content = row['Message Content']
            sender = row['Sender']
            subject = row['Subject']

            # Parse the email using OpenAI
            parsed_email = parse_email(email_content)

            # Send notification via ntfy
            send_notification(parsed_email, sender, subject)
            print(f"Notification sent for email from {sender}")

    except HttpError as error:
        print(f"An error occurred: {error}")

import time
from datetime import datetime, timedelta

if __name__ == "__main__":
    while True:
            # Run main code
            main()

            # Calculate the time until the next hour
            now = datetime.now()
            next_hour = (now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
            sleep_duration = (next_hour - now).total_seconds()

            # Sleep until the next hour
            time.sleep(sleep_duration)

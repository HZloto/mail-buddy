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

# Define a file path to store previous email IDs
PREVIOUS_EMAILS_FILE = "previous_emails.json"

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
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/plain':
                text_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                return clean_text(text_content)
            elif part['mimeType'] == 'text/html':
                html_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                text_content = BeautifulSoup(html_content, "html.parser").get_text()
                return clean_text(text_content)
    elif 'body' in payload and 'data' in payload['body']:
        text_content = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
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

def load_previous_emails():
    if os.path.exists(PREVIOUS_EMAILS_FILE):
        with open(PREVIOUS_EMAILS_FILE, 'r') as f:
            return set(json.load(f))
    return set()

def save_current_emails(email_ids):
    with open(PREVIOUS_EMAILS_FILE, 'w') as f:
        json.dump(list(email_ids), f)

def get_latest_emails(service, num_emails=10):
    results = service.users().messages().list(userId='me', maxResults=num_emails, q="is:inbox").execute()
    messages = results.get('messages', [])

    # Load previous email IDs to identify new emails
    previous_email_ids = load_previous_emails()
    current_email_ids = set()
    email_data = []

    for msg in messages:
        email_id = msg['id']
        current_email_ids.add(email_id)
        
        # Proceed only if email is new
        if email_id not in previous_email_ids:
            message = service.users().messages().get(userId='me', id=email_id, format='full').execute()
            headers = message['payload']['headers']
            date = next((h['value'] for h in headers if h['name'] == 'Date'), "No Date")
            sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown Sender")
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
            
            # Determine category based on labels
            category = get_email_category(message)
            
            # Get the email content
            email_content = get_email_content(message['payload'])

            # Append data to list
            email_data.append({
                "Date Received": date,
                "Sender": sender,
                "Category": category,
                "Message Content": email_content,
                "Subject": subject,
                "Email ID": email_id  # Include Email ID for future reference
            })
        else:
            # Skip emails that have been seen before
            continue

    # Save current email IDs for the next run
    save_current_emails(current_email_ids)

    # Create DataFrame with the modified column order
    df = pd.DataFrame(email_data)
    return df

def parse_email(email_content):
    email_parser_prompt = '''
    You are an email parser. Your task is to assess whether an email seems important and provide a 25-word summary of its contents.
    Label the email as "Important" or "Not Important" based on keywords like deadlines, meetings, urgent tasks, approvals, or action items.
    Then, summarize the key details and main point of the email in exactly 25 words.
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
        result = json.loads(message_content)
    elif isinstance(message_content, dict):
        result = message_content
    else:
        # Handle unexpected types
        print("Error: Unexpected response type from OpenAI API.")
        result = {}

    return result

def send_notification(message_content, sender, subject):
    try:
        importance = message_content.get("importance", "Not Important")
        summary = message_content.get("summary", "")
    except AttributeError:
        # Handle cases where message_content is not a dict
        print("Error: message_content is not a dictionary.")
        return

    # Determine priority
    priority = "low" if importance == "Not Important" else "high"

    # Create the notification message
    notification_title = f"Email from {sender}: {subject}"
    notification_body = summary

    # Normalize notification_title to ASCII
    notification_title = remove_non_ascii(notification_title)

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

def remove_non_ascii(s):
    return ''.join(c if ord(c) < 256 else '?' for c in s)


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
        
        # Fetch the latest emails in a DataFrame
        df = get_latest_emails(service, num_emails=10)

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

if __name__ == "__main__":
    main()

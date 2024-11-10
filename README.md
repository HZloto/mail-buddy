<a href="https://github.com/HZloto/mail-buddy">
  <img alt="Mail Buddy Logo" src="data/mail-buddy-banner.png">
  <h1 align="center">Mail Buddy</h1>
</a>

<p align="center">
  Incoming emails are often overwhelming and rarely important. <br>
  Keep your inbox clutter-free and stay focused with smart email filtering, summarization and notification.
</p>

<p align="center">
  <a href="#features"><strong>Features</strong></a> ·
  <a href="#getting-started"><strong>Getting Started</strong></a> ·
  <a href="#customization"><strong>Customization</strong></a> ·
  <a href="#contributing"><strong>Contributing</strong></a>
</p>

<br/>

<i>Disclaimer: mail buddy only works with gmail for now. feel free to add support for your own email provider.</i>

## Features

- **Smart Filtering**  
  Automatically identifies and prioritizes emails based on their content and importance, helping you focus on what matters.

- **Summarization**  
  Summarizes essential messages so you can quickly get the gist without diving into details.

- **Real-Time Notifications**  
  Alerts you to important emails instantly, keeping you in the loop on the go.

- **Customizable**  
  Set filters to exclude distracting promotional or low-priority emails.

## Getting Started

These instructions will help you set up **Mail Buddy** on your local machine.

### Prerequisites

To run **Mail Buddy**, you’ll need:

- **Python 3.7+**
- **Google Cloud Credentials** for Gmail API access
- **OpenAI API Key** for AI-driven summarization

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/mail-buddy.git
   cd mail-buddy
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   Create a `.env` file with your API keys:

   ```plaintext
   OPENAI_API_KEY=your_openai_api_key
   ```

4. **Configure Google API**:
   - Follow [Google's guide](https://developers.google.com/gmail/api/quickstart/python) to set up the Gmail API and download your `credentials.json` file.
   - Save `credentials.json` in the project root directory.

5. **Configure ntfy**:
   - Follow [ntfy's docs](https://docs.ntfy.sh/) to get the app on your phone and create a channel to use for your own emails
   - Make sure to password protect it if any of the data is sensitive .
   - Replace the `NTFY_TOPIC_URL` variable in the main.py script (line 37) to your channel url (eg https://ntfy.sh/your-name-mail-buddy)

### Usage

To start **Mail Buddy**, run:

```bash
python main.py
```

The assistant will monitor new emails, categorize and summarize messages, and send notifications for priority emails. By default, it checks your inbox every hour.

## Customization

Adjust notification settings, filtering rules, and scheduling within `main.py` to fit your needs. We're currently working on a version of the code hosted directly on a server, coming soon! 

## Contributing

We welcome contributions! Submit a pull request or open an issue to suggest improvements.

---

With **Mail Buddy**, take control of your inbox, focus on the essentials, and minimize distractions.

---

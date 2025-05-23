from flask import Flask, request
from twilio.twiml.messaging_response import MessagingResponse
import requests
import os

app = Flask(__name__)

# Replace with your actual Safe Browsing API key
SAFE_BROWSING_API_KEY = "AIzaSyDLGdpJ-dOnQek61hcaffYlEkuRDTgNBFQ"

def check_link_safety(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(api_url, json=body)
    if response.ok:
        data = response.json()
        if "matches" in data:
            return "⚠️ Warning: This link is potentially unsafe!"
        else:
            return "✅ This link appears safe to visit."
    else:
        return "❌ Error checking the link. Try again later."

@app.route("/sms", methods=['POST'])
def sms_reply():
    incoming_msg = request.form.get('Body')
    resp = MessagingResponse()
    
    if incoming_msg.startswith("http"):
        result = check_link_safety(incoming_msg.strip())
        resp.message(result)
    else:
        resp.message("Please send a valid link starting with http or https.")

    return str(resp)

if __name__ == "__main__":
    app.run(debug=True)

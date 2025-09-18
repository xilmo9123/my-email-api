# 1. IMPORTS
from fastapi import FastAPI, HTTPException, status, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import requests  # For Brevo API calls
import dns.resolver
import asyncio
from enum import Enum
import re

import os

# Get API key from environment variable
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
if not BREVO_API_KEY:
    raise ValueError("BREVO_API_KEY environment variable is not set. Please set it in your Railway project variables.")

BREVO_SENDER_EMAIL = "your-verified-email@yourdomain.com"  # ← Change this too!
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# 2. APP INITIALIZATION
app = FastAPI(title="Email API - Send with Brevo")

# 3. MODELS (Must come BEFORE endpoints that use them)
class EnhancedEmailRequest(BaseModel):
    # REMOVED: sender_email and sender_app_password (no longer needed)
    to_email: EmailStr
    subject: str = "Notification from Our Service"
    plain_text: Optional[str] = Field(None, description="Plain text content")
    html_content: Optional[str] = Field(None, description="HTML content")
    from_name: Optional[str] = Field(None, description="Custom 'From' name")
    reply_to: Optional[EmailStr] = Field(None, description="Custom reply-to address")

    # Validator to ensure we have content
    @validator('*', always=True)
    def check_content(cls, v, values):
        if 'plain_text' in values and 'html_content' in values:
            if values['plain_text'] is None and values['html_content'] is None:
                raise ValueError('Either plain_text or html_content must be provided')
        return v

class EmailResponse(BaseModel):
    status: str
    message: str
    email: str

# 4. BREVO CONFIGURATION
BREVO_API_KEY = "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"  # REPLACE WITH YOUR BREVO API KEY
BREVO_SENDER_EMAIL = "xilmo9123@gmail.com"  # REPLACE WITH EMAIL VERIFIED IN BREVO DASHBOARD
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# 5. FUNCTIONS
async def verify_email_exists(email: str) -> bool:
    """
    Verify if an email address exists by checking its domain and mailbox.
    Returns True for valid domains, but is cautious with major providers.
    """
    try:
        # Basic email format validation
        if '@' not in email:
            print(f"Invalid email format: {email}")
            return False
            
        # Extract and validate domain
        domain = email.split('@')[-1].strip().lower()
        if not domain or '.' not in domain:
            print(f"Invalid domain in email: {email}")
            return False
        
        print(f"Verifying domain: {domain}")
        
        # List of domains that don't allow real SMTP verification
        protected_domains = ['gmail.com', 'googlemail.com', 'yahoo.com', 
                           'outlook.com', 'hotmail.com', 'aol.com', 'icloud.com']
        
        # If it's a major provider, skip deep verification and just validate format
        if domain in protected_domains:
            print(f"Domain {domain} is a major provider. Skipping deep SMTP verification.")
            # Just validate the format is correct
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email))
        
        # Check MX records for other domains
        try:
            records = await asyncio.get_event_loop().run_in_executor(
                None, dns.resolver.resolve, domain, 'MX'
            )
            if not records:
                print(f"No MX records found for domain: {domain}")
                return False
                
            mx_record = str(records[0].exchange)
            print(f"Found MX record: {mx_record}")
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            print(f"DNS resolution failed for domain: {domain}")
            return False
        except Exception as e:
            print(f"DNS error for {domain}: {e}")
            return False
        
        # Attempt SMTP verification for non-major domains
        try:
            import smtplib
            with smtplib.SMTP(mx_record, 25, timeout=10) as server:
                server.ehlo()
                server.mail('verify@example.com')
                code, message = server.rcpt(email)
                print(f"SMTP response for {email}: Code {code}, Message: {message}")
                
                # For most servers, code 250 means mailbox exists
                return code == 250
                
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPResponseException) as e:
            print(f"SMTP connection error for {mx_record}: {e}")
            # If we can't connect, be permissive and let the send attempt happen
            return True
        except Exception as e:
            print(f"SMTP error for {email}: {e}")
            return False
            
    except Exception as e:
        print(f"Unexpected error during verification of {email}: {e}")
        # Be permissive on unexpected errors
        return True

def send_email_via_brevo(
    to_email: str,
    subject: str,
    plain_text: str = None,
    html_content: str = None,
    from_name: str = None,
    reply_to: str = None
):
    """Sends an email using Brevo's HTTPS API"""
    
    # Prepare the payload for Brevo
    payload = {
        "sender": {
            "name": from_name or "Email API Service",
            "email": BREVO_SENDER_EMAIL  # Use your verified Brevo sender email
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content or f"<p>{plain_text}</p>",
        "textContent": plain_text or "Email content"
    }
    
    if reply_to:
        payload["replyTo"] = {"email": reply_to}
    
    # Send via Brevo's HTTPS API
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": BREVO_API_KEY
    }
    
    try:
        response = requests.post(BREVO_API_URL, json=payload, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes
        print(f"Brevo API response: {response.status_code}, {response.json()}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Brevo API error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Brevo API error response: {e.response.text}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send email via Brevo: {str(e)}"
        )

# 6. SECURITY & AUTHENTICATION
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )
    # Simple hardcoded check for testing. REPLACE THIS.
    if api_key != "TEST_KEY_123":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key

# 7. ENDPOINTS
@app.post("/send-email", response_model=EmailResponse)
async def send_email(
    request: EnhancedEmailRequest,
    api_key: str = Security(get_api_key)
):
    """
    Verify an email address and send a message using Brevo email service.
    """
    
    # First, verify the recipient email exists
    is_valid = await verify_email_exists(request.to_email)
    
    if not is_valid:
        return EmailResponse(
            status="error",
            message="Invalid recipient email address. Message not sent.",
            email=request.to_email
        )
    
    # If recipient is valid, send the email using Brevo
    try:
        send_success = send_email_via_brevo(
            to_email=request.to_email,
            subject=request.subject,
            plain_text=request.plain_text,
            html_content=request.html_content,
            from_name=request.from_name,
            reply_to=request.reply_to
        )
        
        if send_success:
            return EmailResponse(
                status="success",
                message="Email successfully sent to valid address.",
                email=request.to_email
            )
            
    except HTTPException as he:
        # Re-raise the HTTP exceptions from the sending function
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

# Health check endpoint
@app.get("/")
async def health_check():
    return {"status": "OK", "service": "Email API with Brevo"}

# Test Brevo connection endpoint
@app.get("/test-brevo")
async def test_brevo_connection():
    """Test if Brevo API connection is working"""
    try:
        headers = {"api-key": BREVO_API_KEY}
        response = requests.get("https://api.brevo.com/v3/account", headers=headers)
        response.raise_for_status()
        return {"status": "success", "message": "Brevo connection is working"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Brevo connection failed: {str(e)}")

# Run the app
if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

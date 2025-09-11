from fastapi import FastAPI, HTTPException, status, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import smtplib
import dns.resolver
import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from enum import Enum
import re

app = FastAPI(title="Email API - Send from Your Own Account")

# --- 1. Security: API Key Authentication (For Your API, Not Gmail) ---
# This is how you will identify and charge your users
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header)):
    # In a real app, you would validate this key against a database
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

# --- 2. New Input Model: Now Includes Sender Credentials ---
class EnhancedEmailRequest(BaseModel):
    # SENDER'S CREDENTIALS (The User of YOUR API)
    sender_email: EmailStr
    sender_app_password: str = Field(..., min_length=1, description="The App Password for the sender's Gmail account. NOT their regular password.")

    # RECIPIENT AND CONTENT
    to_email: EmailStr
    subject: str = "Notification from Our Service"
    plain_text: Optional[str] = Field(None, description="Plain text content")
    html_content: Optional[str] = Field(None, description="HTML content")
    
    # Customization
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

# --- 3. Updated Email Sending Function (Uses User's Credentials) ---
def send_email_on_behalf_of_user(
    sender_email: str,
    sender_app_password: str,
    to_email: str,
    subject: str,
    plain_text: str = None,
    html_content: str = None,
    from_name: str = None,
    reply_to: str = None
):
    """Sends an email using the user's own Gmail account credentials."""
    
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587

    # Create email container
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    # Use the user's email and their chosen name
    msg['From'] = f'"{from_name}" <{sender_email}>' if from_name else sender_email
    msg['To'] = to_email
    msg['Date'] = formatdate(localtime=True)
    
    if reply_to:
        msg['Reply-To'] = reply_to

    # Handle content
    if plain_text is None and html_content is not None:
        plain_text = re.sub('<[^<]+?>', '', html_content)
    elif html_content is None and plain_text is not None:
        html_content = f"<div style='font-family: Arial, sans-serif;'>{plain_text.replace(chr(10), '<br>')}</div>"

    # Create both text and HTML versions
    part1 = MIMEText(plain_text, 'plain')
    part2 = MIMEText(html_content, 'html')
    
    msg.attach(part1)
    msg.attach(part2)
    
    # The Key Change: Log in using the USER'S credentials, not yours.
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(sender_email, sender_app_password) # <-- USER'S CREDENTIALS
            server.send_message(msg)
        return True
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to authenticate with Gmail. Please check your email address and App Password."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email: {str(e)}"
        )

# --- 4. Enhanced API Endpoint ---
@app.post("/send-email", response_model=EmailResponse)
async def send_email(
    request: EnhancedEmailRequest,
    # This ensures the user is authenticated with YOUR API before they can even try to send
    api_key: str = Security(get_api_key)
):
    """
    Verify an email address and send a message using YOUR OWN Gmail account.
    
    **Important:** You must use an App Password, not your regular Gmail password.
    Generate one here: https://myaccount.google.com/apppasswords
    """
    
    # First, verify the recipient email exists
    is_valid = await verify_email_exists(request.to_email)
    
    if not is_valid:
        return EmailResponse(
            status="error",
            message="Invalid recipient email address. Message not sent.",
            email=request.to_email
        )
    
    # If recipient is valid, send the email using the USER'S credentials
    try:
        send_success = send_email_on_behalf_of_user(
            sender_email=request.sender_email,
            sender_app_password=request.sender_app_password,
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

# (Keep your existing verify_email_exists and health_check functions here)
# ... [The rest of your code for verify_email_exists and health_check] ...

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

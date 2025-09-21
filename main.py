# 1. IMPORTS
from fastapi import FastAPI, HTTPException, status, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import dns.resolver
import asyncio
import re
import os
import resend

# 2. APP INITIALIZATION
app = FastAPI(title="Email API - Send with Resend")

# 3. MODELS (Must come BEFORE endpoints that use them)
class EnhancedEmailRequest(BaseModel):
    to_email: EmailStr
    subject: str = "Notification from Our Service"
    plain_text: Optional[str] = Field(None, description="Plain text content")
    html_content: Optional[str] = Field(None, description="HTML content")
    from_name: Optional[str] = Field(None, description="Custom 'From' name")
    reply_to: Optional[EmailStr] = Field(None, description="Custom reply-to address")

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

# 4. RESEND CONFIGURATION
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
if not RESEND_API_KEY:
    raise ValueError("RESEND_API_KEY environment variable is not set. Please set it in your Railway project variables.")

RESEND_SENDER_EMAIL = "xilmo9123@gmail.com"  # <- USE YOUR VERIFIED RESEND EMAIL

# Initialize Resend
resend.api_key = RESEND_API_KEY

# 5. FUNCTIONS
async def verify_email_exists(email: str) -> bool:
    """
    Verify if an email address exists by checking its domain and mailbox.
    Returns True for valid domains, but is cautious with major providers.
    """
    try:
        if '@' not in email:
            print(f"Invalid email format: {email}")
            return False
            
        domain = email.split('@')[-1].strip().lower()
        if not domain or '.' not in domain:
            print(f"Invalid domain in email: {email}")
            return False
        
        protected_domains = ['gmail.com', 'googlemail.com', 'yahoo.com', 
                           'outlook.com', 'hotmail.com', 'aol.com', 'icloud.com']
        
        if domain in protected_domains:
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email))
        
        try:
            records = await asyncio.get_event_loop().run_in_executor(
                None, dns.resolver.resolve, domain, 'MX'
            )
            if not records:
                print(f"No MX records found for domain: {domain}")
                return False
                
            mx_record = str(records[0].exchange)
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            print(f"DNS resolution failed for domain: {domain}")
            return False
        except Exception as e:
            print(f"DNS error for {domain}: {e}")
            return False
        
        try:
            import smtplib
            with smtplib.SMTP(mx_record, 25, timeout=10) as server:
                server.ehlo()
                server.mail('verify@example.com')
                code, message = server.rcpt(email)
                return code == 250
                
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPResponseException):
            return True
        except Exception:
            return False
            
    except Exception:
        return True

def send_email_via_resend(
    to_email: str,
    subject: str,
    plain_text: str = None,
    html_content: str = None,
    from_name: str = None,
    reply_to: str = None
):
    """Sends an email using Resend's API"""
    
    from_email = f"{from_name} <{RESEND_SENDER_EMAIL}>" if from_name else RESEND_SENDER_EMAIL

    try:
        params = {
            "from": from_email,
            "to": [to_email],
            "subject": subject,
            "text": plain_text,
            "html": html_content,
        }
        
        if reply_to:
            params["reply_to"] = reply_to

        email_response = resend.Emails.send(params)
        print(f"Resend response: {email_response}")
        return True
        
    except Exception as e:
        print(f"Resend API error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send email via Resend: {str(e)}"
        )

# 6. SECURITY & AUTHENTICATION
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )
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
    Verify an email address and send a message using Resend email service.
    """
    
    is_valid = await verify_email_exists(request.to_email)
    
    if not is_valid:
        return EmailResponse(
            status="error",
            message="Invalid recipient email address. Message not sent.",
            email=request.to_email
        )
    
    try:
        send_success = send_email_via_resend(
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
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

# Health check endpoint
@app.get("/")
async def health_check():
    return {"status": "OK", "service": "Email API with Resend"}

# Test Resend connection endpoint - FIXED VERSION
@app.get("/test-resend")
async def test_resend_connection():
    """Test if Resend API connection is working"""
    try:
        # Simple test: try to send a basic request to Resend
        # This avoids the problematic ApiKeys.get() method
        test_params = {
            "from": "test@resend.dev",  # Use a test email
            "to": "test@example.com",   # Any email will work for validation
            "subject": "Connection Test",
            "text": "This is a connection test",
        }
        
        # This will validate the API key without sending an actual email
        # if the parameters are invalid (like using resend.dev domain)
        resend.Emails.send(test_params)
        
        return {"status": "success", "message": "Resend API key is valid and connection is working"}
        
    except resend.ResendError as e:
        # If we get a ResendError, it means the API key is working but there's a parameter issue
        if "invalid domain" in str(e).lower() or "from" in str(e).lower():
            return {"status": "success", "message": "Resend API key is valid (domain validation error is expected)"}
        raise HTTPException(status_code=500, detail=f"Resend connection failed: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Resend connection failed: {str(e)}")

# Run the app
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

"""Quick SMTP connectivity test."""
import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

user = os.getenv("EMAIL_USER", "").strip()
pwd = os.getenv("EMAIL_PASS", "").strip()

print(f"EMAIL_USER: {user}")
print(f"EMAIL_PASS: {'*' * len(pwd)} ({len(pwd)} chars)")
print()

if not user or not pwd:
    print("SMTP NOT CONFIGURED - missing credentials")
else:
    print("Connecting to smtp.gmail.com:587...")
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=15)
        server.ehlo()
        print("  EHLO ... OK")
        server.starttls()
        print("  STARTTLS ... OK")
        server.ehlo()
        server.login(user, pwd)
        print("  LOGIN ... OK")
        server.quit()
        print()
        print("=" * 40)
        print("SMTP IS FULLY WORKING!")
        print("=" * 40)
    except smtplib.SMTPAuthenticationError as e:
        print(f"  AUTH FAILED: {e}")
        print("  -> Check your Gmail App Password.")
    except Exception as e:
        print(f"  CONNECTION FAILED: {e}")

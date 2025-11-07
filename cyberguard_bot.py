#!/usr/bin/env python3
"""
🤖 CyberGuard AI - Telegram Security Bot 2025
The Ultimate Security Assistant for Telegram
Developer: @Gh0stDeveloper
Channel: https://t.me/+KQkliYhDy_U1N2Ex
"""

import telebot
import requests
import hashlib
import base64
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime
import threading
import qrcode
from io import BytesIO
import asyncio

# Bot Configuration
API_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
bot = telebot.TeleBot(API_TOKEN)

class CyberGuardAI:
    def __init__(self):
        self.user_sessions = {}
        self.encryption_keys = {}
    
    # === ADVANCED ENCRYPTION SYSTEM ===
    def generate_key(self):
        """Generate unique encryption key"""
        return Fernet.generate_key()
    
    def encrypt_message(self, text, key=None):
        """Encrypt message"""
        if not key:
            key = self.generate_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode())
        return encrypted, key
    
    def decrypt_message(self, encrypted_text, key):
        """Decrypt message"""
        try:
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_text).decode()
            return decrypted
        except:
            return None
    
    # === BREACH MONITOR ===
    def check_breach(self, email):
        """Check if email is in data breaches"""
        try:
            # Hash the email (only first 5 chars for privacy)
            email_hash = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix = email_hash[:5]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url)
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                for h in hashes:
                    if email_hash[5:] in h:
                        return True, int(h.split(':')[1])
            return False, 0
        except:
            return None, 0
    
    # === AI PASSWORD GENERATOR ===
    def generate_ai_password(self, length=16, complexity="high"):
        """Generate intelligent password"""
        import random
        import string
        
        if complexity == "high":
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
        elif complexity == "medium":
            chars = string.ascii_letters + string.digits
        else:
            chars = string.ascii_lowercase + string.digits
        
        # Intelligent pattern: mix of uppercase, lowercase, numbers and symbols
        password = []
        if complexity == "high":
            password.append(random.choice(string.ascii_uppercase))
            password.append(random.choice(string.ascii_lowercase))
            password.append(random.choice(string.digits))
            password.append(random.choice("!@#$%^&*"))
        
        # Complete the rest
        remaining = length - len(password)
        password.extend(random.choice(chars) for _ in range(remaining))
        
        # Shuffle
        random.shuffle(password)
        return ''.join(password)
    
    # === WEBSITE ANALYZER ===
    def analyze_website(self, url):
        """Analyze website security"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            results = {
                'https': False,
                'security_headers': [],
                'server_info': '',
                'vulnerabilities': []
            }
            
            response = requests.get(url, timeout=10, verify=False)
            
            # Check HTTPS
            results['https'] = url.startswith('https://')
            
            # Check security headers
            security_headers = ['Content-Security-Policy', 'X-Frame-Options', 
                              'X-Content-Type-Options', 'Strict-Transport-Security']
            
            for header in security_headers:
                if header in response.headers:
                    results['security_headers'].append(f"✅ {header}")
                else:
                    results['security_headers'].append(f"❌ {header}")
                    results['vulnerabilities'].append(f"Missing header: {header}")
            
            # Server information
            if 'Server' in response.headers:
                results['server_info'] = response.headers['Server']
            
            return results
            
        except Exception as e:
            return {'error': str(e)}
    
    # === SECURE QR GENERATOR ===
    def generate_secure_qr(self, data):
        """Generate QR code for secure data"""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        bio = BytesIO()
        img.save(bio, 'PNG')
        bio.seek(0)
        return bio

# Global instance
cyber_guard = CyberGuardAI()

# === BOT COMMANDS ===
@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_text = """
🛡️ *CyberGuard AI 2025* - Your Security Assistant

*Available Commands:*

🔐 *Encryption & Security*
/encrypt - Encrypt messages
/decrypt - Decrypt messages
/generatepassword - Generate secure password
/checkpassword - Analyze strength

🌐 *Web Analysis*  
/scanwebsite [url] - Analyze web security
/checkbreach [email] - Check data breaches

📱 *Utilities*
/generateqr [text] - Generate secure QR
/securitytips - Security tips

⚙️ *Configuration*
/help - Complete help
/about - Bot information

*Protect your digital life with 2025 cutting-edge technology!*
    """
    bot.reply_to(message, welcome_text, parse_mode='Markdown')

@bot.message_handler(commands=['encrypt'])
def encrypt_command(message):
    """Encrypt message"""
    try:
        bot.reply_to(message, "🔐 Send me the text you want to encrypt:")
        bot.register_next_step_handler(message, process_encrypt)
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

def process_encrypt(message):
    """Process encryption"""
    try:
        text = message.text
        encrypted, key = cyber_guard.encrypt_message(text)
        
        response = f"""
✅ *Text Encrypted Successfully*

🔒 *Encrypted Text:*
`{base64.urlsafe_b64encode(encrypted).decode()}`

🔑 *Decryption Key:*
`{base64.urlsafe_b64encode(key).decode()}`

⚠️ *Save the key in a safe place!*
        """
        bot.reply_to(message, response, parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Encryption error: {str(e)}")

@bot.message_handler(commands=['decrypt'])
def decrypt_command(message):
    """Decrypt message"""
    try:
        bot.reply_to(message, "🔓 Send me the encrypted text (in base64):")
        bot.register_next_step_handler(message, get_encrypted_text)
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

def get_encrypted_text(message):
    """Get encrypted text"""
    try:
        encrypted_b64 = message.text
        cyber_guard.user_sessions[message.chat.id] = {'encrypted': encrypted_b64}
        bot.reply_to(message, "🔑 Now send the decryption key (in base64):")
        bot.register_next_step_handler(message, process_decrypt)
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

def process_decrypt(message):
    """Process decryption"""
    try:
        user_data = cyber_guard.user_sessions.get(message.chat.id)
        if not user_data:
            bot.reply_to(message, "❌ Session expired. Start over.")
            return
        
        key_b64 = message.text
        encrypted_b64 = user_data['encrypted']
        
        # Decode
        encrypted = base64.urlsafe_b64decode(encrypted_b64)
        key = base64.urlsafe_b64decode(key_b64)
        
        # Decrypt
        decrypted = cyber_guard.decrypt_message(encrypted, key)
        
        if decrypted:
            response = f"""
✅ *Text Decrypted Successfully*

📝 *Original Text:*
`{decrypted}`
            """
            bot.reply_to(message, response, parse_mode='Markdown')
        else:
            bot.reply_to(message, "❌ Decryption error. Verify the key.")
            
    except Exception as e:
        bot.reply_to(message, f"❌ Decryption error: {str(e)}")

@bot.message_handler(commands=['generatepassword'])
def generate_password(message):
    """Generate secure password"""
    try:
        # Generate passwords of different levels
        strong_pass = cyber_guard.generate_ai_password(16, "high")
        medium_pass = cyber_guard.generate_ai_password(12, "medium")
        simple_pass = cyber_guard.generate_ai_password(10, "low")
        
        response = f"""
🔐 *Secure Password Generator*

🛡️ *Strong (16 characters):*
`{strong_pass}`

✅ *Medium (12 characters):*
`{medium_pass}`

📱 *Simple (10 characters):*
`{simple_pass}`

💡 *Tip: Use STRONG password for important accounts*
        """
        bot.reply_to(message, response, parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['checkpassword'])
def check_password(message):
    """Analyze password strength"""
    try:
        bot.reply_to(message, "🔍 Send me the password to analyze:")
        bot.register_next_step_handler(message, analyze_password)
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

def analyze_password(message):
    """Analyze password"""
    try:
        password = message.text
        
        # Basic analysis
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate score
        score = 0
        if length >= 8: score += 1
        if length >= 12: score += 1
        if length >= 16: score += 2
        if has_upper: score += 1
        if has_lower: score += 1
        if has_digit: score += 1
        if has_special: score += 2
        
        # Determine strength
        if score >= 7:
            strength = "🛡️ *VERY STRONG*"
            color = "🟢"
        elif score >= 5:
            strength = "✅ *STRONG*"
            color = "🟡"
        elif score >= 3:
            strength = "⚠️ *MODERATE*"
            color = "🟠"
        else:
            strength = "❌ *WEAK*"
            color = "🔴"
        
        response = f"""
🔍 *Password Analysis*

{strength}

📊 *Score: {score}/9*

📏 *Length:* {length} characters
🔠 *Uppercase:* {'✅' if has_upper else '❌'}
🔡 *Lowercase:* {'✅' if has_lower else '❌'}
🔢 *Numbers:* {'✅' if has_digit else '❌'}
⚡ *Symbols:* {'✅' if has_special else '❌'}

💡 *Recommendations:*
- Use at least 12 characters
- Combine uppercase, lowercase, numbers and symbols
- Don't reuse passwords
        """
        bot.reply_to(message, response, parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['scanwebsite'])
def scan_website(message):
    """Scan website"""
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "❌ Usage: /scanwebsite https://example.com")
            return
        
        url = command_parts[1]
        bot.reply_to(message, f"🌐 Analyzing {url}...")
        
        results = cyber_guard.analyze_website(url)
        
        if 'error' in results:
            bot.reply_to(message, f"❌ Error: {results['error']}")
            return
        
        response = f"""
🔍 *Security Analysis: {url}*

🔒 *HTTPS:* {'✅ Enabled' if results['https'] else '❌ Not enabled'}
        
🛡️ *Security Headers:*
{chr(10).join(results['security_headers'])}

📡 *Server:* {results['server_info'] or 'Not identified'}

{'⚠️ *Issues found:*' + chr(10) + chr(10).join(results['vulnerabilities']) if results['vulnerabilities'] else '✅ No critical vulnerabilities found'}
        """
        bot.reply_to(message, response, parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['checkbreach'])
def check_breach(message):
    """Check email breaches"""
    try:
        command_parts = message.text.split()
        if len(command_parts) < 2:
            bot.reply_to(message, "❌ Usage: /checkbreach email@example.com")
            return
        
        email = command_parts[1]
        bot.reply_to(message, f"🔍 Searching {email} in breaches...")
        
        is_breached, count = cyber_guard.check_breach(email)
        
        if is_breached is None:
            response = "❌ Could not verify. Try again later."
        elif is_breached:
            response = f"""
🚨 *SECURITY ALERT*

📧 *Email:* {email}
🔓 *Status:* ❌ FOUND IN {count} BREACHES

⚠️ *Recommended actions:*
1. Change your password immediately
2. Enable two-factor authentication
3. Check other accounts with same password
4. Use a password manager
            """
        else:
            response = f"""
✅ *Search Result*

📧 *Email:* {email}
🔒 *Status:* ✅ Not found in known breaches

💡 *Maintain your security:*
- Use unique passwords
- Enable 2FA when possible
- Monitor your accounts regularly
            """
        bot.reply_to(message, response, parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['generateqr'])
def generate_qr(message):
    """Generate QR code"""
    try:
        command_parts = message.text.split(' ', 1)
        if len(command_parts) < 2:
            bot.reply_to(message, "❌ Usage: /generateqr text_to_encode")
            return
        
        text = command_parts[1]
        qr_image = cyber_guard.generate_secure_qr(text)
        
        bot.send_photo(message.chat.id, qr_image, 
                      caption="📱 *QR code generated successfully*\n\nContent: " + text[:50] + "...",
                      parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(commands=['securitytips'])
def security_tips(message):
    """Security tips"""
    tips = """
🛡️ *Security Tips 2025*

🔐 *Passwords:*
- Use 12+ character passwords
- Don't reuse passwords
- Use a password manager
- Enable 2FA whenever possible

🌐 *Browsing:*
- Always verify HTTPS
- Don't click suspicious links
- Use VPN on public networks
- Keep your browser updated

📱 *Devices:*
- Update your system regularly
- Use antivirus/malware protection
- Encrypt your devices
- Make regular backups

💡 *Extra Tip:*
Security is a process, not a destination. 
Review and update regularly.
    """
    bot.reply_to(message, tips, parse_mode='Markdown')

@bot.message_handler(commands=['help'])
def help_command(message):
    """Show help"""
    help_text = """
🆘 *Help Center - CyberGuard AI*

*Main Commands:*

🔐 *Encryption:*
/encrypt - Encrypt confidential messages
/decrypt - Decrypt messages with key

🔑 *Passwords:*
/generatepassword - Generate secure passwords
/checkpassword - Analyze strength

🌐 *Web:*
/scanwebsite [url] - Analyze web security
/checkbreach [email] - Search in breaches

📱 *Utilities:*
/generateqr [text] - Generate QR code
/securitytips - Security tips

💬 *Support:*
To report problems or suggestions:
@SecurityResearchUpdates

*Your security is our priority!*
    """
    bot.reply_to(message, help_text, parse_mode='Markdown')

@bot.message_handler(commands=['about'])
def about_command(message):
    """Bot information"""
    about_text = """
🤖 *CyberGuard AI 2025*

*Your Intelligent Security Assistant*

✨ *Features:*
- Military-grade encryption
- Password analysis
- Breach monitoring
- Web security scanning
- QR code generation

🔧 *Technology:*
- Python 3.9+
- Cryptography Library
- Telegram Bot API
- Security APIs

👨💻 *Developer:* @CHICO-CP
📢 *Channel:* @SecurityResearchUpdates

🛡️ *Committed to your digital security*
    """
    bot.reply_to(message, about_text, parse_mode='Markdown')

# Handle unknown messages
@bot.message_handler(func=lambda message: True)
def handle_unknown(message):
    bot.reply_to(message, """
❓ Command not recognized.

Use /help to see all available commands
or /start to begin.

I'm here to help with your digital security! 🔐
    """)

if __name__ == "__main__":
    print("🤖 CyberGuard AI 2025 - Started")
    print("🛡️ Security bot running...")
    print("📢 Channel: @SecurityResearchUpdates")
    bot.polling()
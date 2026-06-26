"""
Safety guardrails for QueueStorm Investigator.
These rules are hard-coded and cannot be overridden by complaint text.
"""

import re

# Keywords that indicate a customer_reply is requesting credentials (BAD)
CREDENTIAL_REQUEST_PATTERNS = [
    r'\bshare\s+(your\s+)?(pin|otp|password|passcode|card\s+number)\b',
    r'\bprovide\s+(your\s+)?(pin|otp|password|passcode|card\s+number)\b',
    r'\benter\s+(your\s+)?(pin|otp|password|passcode|card\s+number)\b',
    r'\bsend\s+(your\s+)?(pin|otp|password|passcode|card\s+number)\b',
    r'\bgive\s+(your\s+)?(pin|otp|password|passcode|card\s+number)\b',
    r'\bverif(y|ication)\s+(your\s+)?(pin|otp|password|passcode)\b',
    r'\bwhat\s+is\s+your\s+(pin|otp|password)\b',
]

# Keywords that indicate unauthorized refund promise (BAD)
UNAUTHORIZED_REFUND_PATTERNS = [
    r'\bwe\s+will\s+refund\s+you\b',
    r'\byour\s+money\s+will\s+be\s+refunded\b',
    r'\bwe\s+guarantee\s+(a\s+)?refund\b',
    r'\bwe\s+will\s+reverse\s+the\s+transaction\b',
    r'\byou\s+will\s+receive\s+your\s+money\s+back\b',
    r'\bwe\s+will\s+unblock\s+your\s+account\b',
    r'\byour\s+account\s+will\s+be\s+unblocked\b',
]

# Safe alternative phrases to use instead
SAFE_REFUND_LANGUAGE = "any eligible amount will be returned through official channels"

SAFE_CREDENTIAL_REMINDER = "Please do not share your PIN or OTP with anyone."

def check_safety_violations(customer_reply: str) -> list:
    """
    Returns a list of safety violation types found in the customer_reply.
    Empty list means the reply is safe.
    """
    violations = []
    reply_lower = customer_reply.lower()

    for pattern in CREDENTIAL_REQUEST_PATTERNS:
        if re.search(pattern, reply_lower):
            violations.append('credential_request')
            break

    for pattern in UNAUTHORIZED_REFUND_PATTERNS:
        if re.search(pattern, reply_lower):
            violations.append('unauthorized_refund_promise')
            break

    return violations


def detect_prompt_injection(complaint: str) -> bool:
    """
    Detects if the complaint text contains prompt injection attempts.
    Returns True if injection is detected.
    """
    injection_patterns = [
        r'ignore\s+(previous|above|all)\s+instructions',
        r'forget\s+(previous|above|all)\s+instructions',
        r'you\s+are\s+now\s+a',
        r'act\s+as\s+(if\s+you\s+are|a)',
        r'new\s+instructions:',
        r'system\s+prompt:',
        r'override\s+(safety|rules|system)',
        r'jailbreak',
        r'do\s+anything\s+now',
        r'pretend\s+you\s+are',
        r'reveal\s+your\s+(system\s+prompt|instructions)',
    ]
    complaint_lower = complaint.lower()
    for pattern in injection_patterns:
        if re.search(pattern, complaint_lower):
            return True
    return False


def make_safe_customer_reply(
    ticket_id: str,
    relevant_transaction_id: str,
    case_type: str,
    department: str,
    language: str = 'en'
) -> str:
    """
    Generate a safe customer reply based on case type.
    Never promises refunds. Never asks for credentials.
    """
    tx_mention = f" regarding transaction {relevant_transaction_id}" if relevant_transaction_id else ""

    if language == 'bn':
        # Bangla reply
        if relevant_transaction_id:
            return (
                f"আপনার লেনদেন {relevant_transaction_id} এর বিষয়ে আমরা অবগত হয়েছি। "
                f"আমাদের দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। "
                f"অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
            )
        else:
            return (
                f"আপনার সমস্যাটি আমরা নথিভুক্ত করেছি। "
                f"আমাদের দল শীঘ্রই আপনার সাথে অফিসিয়াল চ্যানেলে যোগাযোগ করবে। "
                f"অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
            )

    # English replies by case type
    if case_type == 'phishing_or_social_engineering':
        return (
            "Thank you for reaching out before sharing any information. "
            "We never ask for your PIN, OTP, or password under any circumstances. "
            "Please do not share these with anyone, even if they claim to be from us. "
            "Our fraud team has been notified of this incident."
        )

    elif case_type == 'wrong_transfer':
        return (
            f"We have noted your concern{tx_mention}. "
            f"Please do not share your PIN or OTP with anyone. "
            f"Our dispute team will review the case and contact you through official support channels. "
            f"Any eligible amount will be returned through official channels."
        )

    elif case_type == 'payment_failed':
        return (
            f"We have noted that transaction{tx_mention} may have caused an unexpected balance deduction. "
            f"Our payments team will review the case and any eligible amount will be returned through official channels. "
            f"Please do not share your PIN or OTP with anyone."
        )

    elif case_type == 'duplicate_payment':
        return (
            f"We have noted the possible duplicate payment{tx_mention}. "
            f"Our payments team will verify with the biller and any eligible amount will be returned through official channels. "
            f"Please do not share your PIN or OTP with anyone."
        )

    elif case_type == 'refund_request':
        return (
            f"Thank you for reaching out{tx_mention}. "
            f"Refunds for completed merchant payments depend on the merchant's own policy. "
            f"We recommend contacting the merchant directly. "
            f"If you need help reaching them, please reply and we will guide you. "
            f"Please do not share your PIN or OTP with anyone."
        )

    elif case_type == 'merchant_settlement_delay':
        return (
            f"We have noted your concern about settlement{tx_mention}. "
            f"Our merchant operations team will check the batch status and update you on the expected settlement time through official channels."
        )

    elif case_type == 'agent_cash_in_issue':
        return (
            f"We have noted your concern{tx_mention}. "
            f"Our agent operations team will investigate this promptly and contact you through official channels. "
            f"Please do not share your PIN or OTP with anyone."
        )

    elif case_type == 'other':
        return (
            f"Thank you for reaching out. "
            f"To help you faster, please share the transaction ID, the amount involved, and a short description of what went wrong. "
            f"Please do not share your PIN or OTP with anyone."
        )

    else:
        return (
            f"We have received your request{tx_mention}. "
            f"Our support team will review your case and contact you through official channels. "
            f"Please do not share your PIN or OTP with anyone."
        )
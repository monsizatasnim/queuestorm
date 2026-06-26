"""
Core reasoning logic for QueueStorm Investigator.
Analyzes complaint text against transaction history to produce
evidence-based classifications.
"""

import re
from datetime import datetime, timezone
from typing import Optional


# ─────────────────────────────────────────────────────────────
# KEYWORD MAPS FOR CLASSIFICATION
# ─────────────────────────────────────────────────────────────

WRONG_TRANSFER_KEYWORDS = [
    'wrong number', 'wrong person', 'wrong recipient', 'wrong account',
    'sent to wrong', 'mistakenly sent', 'sent by mistake', 'wrong transfer',
    'ভুল নম্বর', 'ভুল মানুষ', 'ভুল একাউন্ট', 'ভুলে পাঠিয়েছি',
    'wrong mobile', 'wrong phone',
]

PAYMENT_FAILED_KEYWORDS = [
    'payment failed', 'transaction failed', 'failed but', 'balance deducted',
    'money deducted', 'deducted but', 'failed payment', 'recharge failed',
    'bill payment failed', 'payment not successful', 'deducted twice',
    'app showed failed', 'showed error',
]

REFUND_REQUEST_KEYWORDS = [
    'refund', 'money back', 'return my money', 'give back', 'cancel',
    'changed my mind', 'want to return', 'get refund', 'আমার টাকা ফেরত',
    'ফেরত দিন', 'রিফান্ড',
]

DUPLICATE_PAYMENT_KEYWORDS = [
    'charged twice', 'deducted twice', 'duplicate', 'double payment',
    'paid twice', 'two times', 'charged two times', 'billed twice',
    'double charge', 'two payments', '2 times deducted',
]

MERCHANT_SETTLEMENT_KEYWORDS = [
    'settlement', 'not settled', 'settlement delay', 'settlement not received',
    'merchant settlement', 'my sales', 'payment not received',
    'settlement pending',
]

AGENT_CASH_IN_KEYWORDS = [
    'cash in', 'cash-in', 'agent', 'balance not updated', 'balance not received',
    'deposited but', 'cash deposit', 'ক্যাশ ইন', 'এজেন্ট', 'ব্যালেন্সে আসেনি',
    'balance nai', 'cashing', 'cash in not reflected',
]

PHISHING_KEYWORDS = [
    'someone called', 'called me saying', 'asked for otp', 'asked for pin',
    'asked for password', 'asking for otp', 'asking for pin',
    'claiming to be', 'they said account will be blocked',
    'account will be blocked', 'share otp', 'share pin',
    'suspicious call', 'fraud call', 'scam', 'phishing',
    'told me to share', 'unknown person called',
]


def detect_language(complaint: str, language_hint: str = None) -> str:
    """Detect if complaint is Bangla, English, or mixed."""
    if language_hint and language_hint in ['en', 'bn', 'mixed']:
        return language_hint

    # Check for Bangla Unicode characters
    bangla_chars = len(re.findall(r'[\u0980-\u09FF]', complaint))
    total_chars = len(complaint.replace(' ', ''))

    if total_chars == 0:
        return 'en'

    bangla_ratio = bangla_chars / total_chars
    if bangla_ratio > 0.5:
        return 'bn'
    elif bangla_ratio > 0.1:
        return 'mixed'
    return 'en'


def classify_complaint(complaint: str, user_type: str = 'customer') -> str:
    """
    Classify the complaint into one of the case_type enum values.
    Uses keyword matching against the complaint text.
    """
    complaint_lower = complaint.lower()

    # Check phishing first (highest priority for safety)
    for kw in PHISHING_KEYWORDS:
        if kw in complaint_lower:
            return 'phishing_or_social_engineering'

    # Check duplicate payment BEFORE payment_failed (more specific)
    dup_score = sum(1 for kw in DUPLICATE_PAYMENT_KEYWORDS if kw in complaint_lower)
    if dup_score >= 1:
        return 'duplicate_payment'

    # Check merchant settlement (user_type helps)
    if user_type == 'merchant':
        for kw in MERCHANT_SETTLEMENT_KEYWORDS:
            if kw in complaint_lower:
                return 'merchant_settlement_delay'

    for kw in MERCHANT_SETTLEMENT_KEYWORDS:
        if kw in complaint_lower:
            return 'merchant_settlement_delay'

    # Check agent cash-in
    for kw in AGENT_CASH_IN_KEYWORDS:
        if kw in complaint_lower:
            return 'agent_cash_in_issue'

    # Check wrong transfer
    for kw in WRONG_TRANSFER_KEYWORDS:
        if kw in complaint_lower:
            return 'wrong_transfer'

    # Check payment failed
    for kw in PAYMENT_FAILED_KEYWORDS:
        if kw in complaint_lower:
            return 'payment_failed'

    # Check refund request
    for kw in REFUND_REQUEST_KEYWORDS:
        if kw in complaint_lower:
            return 'refund_request'

    # Default
    return 'other'


def get_department(case_type: str) -> str:
    """Map case_type to the responsible department."""
    mapping = {
        'wrong_transfer': 'dispute_resolution',
        'payment_failed': 'payments_ops',
        'refund_request': 'customer_support',
        'duplicate_payment': 'payments_ops',
        'merchant_settlement_delay': 'merchant_operations',
        'agent_cash_in_issue': 'agent_operations',
        'phishing_or_social_engineering': 'fraud_risk',
        'other': 'customer_support',
    }
    return mapping.get(case_type, 'customer_support')


def extract_amount_from_complaint(complaint: str) -> Optional[float]:
    """Try to extract a monetary amount mentioned in the complaint."""
    # Match patterns like "5000 taka", "BDT 1200", "1,500 taka", "৳500"
    patterns = [
        r'(\d[\d,]*)\s*(?:taka|bdt|tk|৳)',
        r'(?:taka|bdt|tk|৳)\s*(\d[\d,]*)',
        r'(\d[\d,]+)\s*(?:to|from|of)',
    ]
    for pattern in patterns:
        match = re.search(pattern, complaint.lower())
        if match:
            amount_str = match.group(1).replace(',', '')
            try:
                return float(amount_str)
            except ValueError:
                continue
    return None


def find_relevant_transaction(
    complaint: str,
    transaction_history: list,
    case_type: str,
) -> tuple[Optional[str], str, float]:
    """
    Find the most relevant transaction from history based on complaint.

    Returns:
        (transaction_id or None, evidence_verdict, confidence)
        evidence_verdict: 'consistent', 'inconsistent', 'insufficient_data'
    """
    if not transaction_history:
        return None, 'insufficient_data', 0.5

    complaint_lower = complaint.lower()
    mentioned_amount = extract_amount_from_complaint(complaint)

    # ── Special handling by case type ──────────────────────────────────────

    if case_type == 'phishing_or_social_engineering':
        # No transaction needed for phishing reports
        return None, 'insufficient_data', 0.95

    if case_type == 'merchant_settlement_delay':
        settlements = [
            t for t in transaction_history
            if t.get('type') == 'settlement'
        ]
        if settlements:
            best = max(settlements, key=lambda t: t.get('timestamp', ''))
            return best['transaction_id'], 'consistent', 0.92
        return None, 'insufficient_data', 0.5

    if case_type == 'agent_cash_in_issue':
        cash_ins = [
            t for t in transaction_history
            if t.get('type') == 'cash_in'
        ]
        if cash_ins:
            # Prefer pending ones
            pending = [t for t in cash_ins if t.get('status') == 'pending']
            if pending:
                return pending[0]['transaction_id'], 'consistent', 0.88
            return cash_ins[0]['transaction_id'], 'consistent', 0.80
        return None, 'insufficient_data', 0.4

    if case_type == 'duplicate_payment':
        payments = [
            t for t in transaction_history
            if t.get('type') in ['payment', 'transfer']
            and t.get('status') == 'completed'
        ]
        if mentioned_amount:
            payments = [p for p in payments if abs(p.get('amount', 0) - mentioned_amount) < 0.01]

        # Group by counterparty and amount to find duplicates
        seen = {}
        for p in sorted(payments, key=lambda x: x.get('timestamp', '')):
            key = (p.get('counterparty', ''), p.get('amount', 0))
            if key in seen:
                # This is the duplicate (second occurrence)
                return p['transaction_id'], 'consistent', 0.93
            seen[key] = p

        if payments:
            return payments[-1]['transaction_id'], 'inconsistent', 0.5
        return None, 'insufficient_data', 0.4

    if case_type == 'payment_failed':
        failed_payments = [
            t for t in transaction_history
            if t.get('type') in ['payment', 'transfer']
            and t.get('status') == 'failed'
        ]
        if mentioned_amount and failed_payments:
            exact = [t for t in failed_payments if abs(t.get('amount', 0) - mentioned_amount) < 0.01]
            if exact:
                return exact[0]['transaction_id'], 'consistent', 0.90
        if failed_payments:
            return failed_payments[0]['transaction_id'], 'consistent', 0.80
        # No failed transactions found - could still be a balance deduction issue
        if mentioned_amount:
            completed = [
                t for t in transaction_history
                if t.get('type') in ['payment', 'transfer']
                and t.get('status') == 'completed'
                and abs(t.get('amount', 0) - mentioned_amount) < 0.01
            ]
            if completed:
                return completed[0]['transaction_id'], 'consistent', 0.85
        return None, 'insufficient_data', 0.5

    if case_type == 'wrong_transfer':
        transfers = [
            t for t in transaction_history
            if t.get('type') == 'transfer'
            and t.get('status') == 'completed'
        ]

        if mentioned_amount and transfers:
            exact = [t for t in transfers if abs(t.get('amount', 0) - mentioned_amount) < 0.01]
            if exact:
                # Check for established recipient pattern (inconsistency signal)
                tx = exact[0]
                same_recipient_count = sum(
                    1 for t in transaction_history
                    if t.get('counterparty') == tx.get('counterparty')
                    and t['transaction_id'] != tx['transaction_id']
                )
                if same_recipient_count >= 2:
                    return tx['transaction_id'], 'inconsistent', 0.75
                elif same_recipient_count == 1:
                    # One prior - borderline
                    return tx['transaction_id'], 'inconsistent', 0.70
                return tx['transaction_id'], 'consistent', 0.90

        if transfers:
            tx = transfers[-1]  # Most recent
            if mentioned_amount:
                return tx['transaction_id'], 'inconsistent', 0.60
            # Multiple transfers of same amount = ambiguous
            if len(transfers) > 1:
                amounts = [t.get('amount', 0) for t in transfers]
                unique_amounts = set(amounts)
                if len(unique_amounts) == 1:
                    # All same amount - ambiguous
                    return None, 'insufficient_data', 0.65
            return tx['transaction_id'], 'consistent', 0.75

        return None, 'insufficient_data', 0.4

    if case_type == 'refund_request':
        payments = [
            t for t in transaction_history
            if t.get('type') == 'payment'
            and t.get('status') == 'completed'
        ]
        if mentioned_amount:
            exact = [t for t in payments if abs(t.get('amount', 0) - mentioned_amount) < 0.01]
            if exact:
                return exact[0]['transaction_id'], 'consistent', 0.85
        if payments:
            return payments[-1]['transaction_id'], 'consistent', 0.75
        return None, 'insufficient_data', 0.5

    # Default: try to find any matching transaction by amount
    if mentioned_amount:
        for tx in sorted(transaction_history, key=lambda x: x.get('timestamp', ''), reverse=True):
            if abs(tx.get('amount', 0) - mentioned_amount) < 0.01:
                return tx['transaction_id'], 'consistent', 0.65

    # No match
    return None, 'insufficient_data', 0.5


def determine_severity(
    case_type: str,
    evidence_verdict: str,
    amount: Optional[float],
    transaction_status: Optional[str] = None,
    human_needed: bool = False,
) -> str:
    """Determine severity based on case type, amount, and evidence."""

    if case_type == 'phishing_or_social_engineering':
        return 'critical'

    if case_type in ['wrong_transfer', 'duplicate_payment', 'payment_failed']:
        if amount and amount >= 10000:
            return 'critical'
        if amount and amount >= 2000:
            return 'high'
        return 'high'  # Default for these case types

    if case_type == 'agent_cash_in_issue':
        return 'high'

    if case_type == 'merchant_settlement_delay':
        if amount and amount >= 10000:
            return 'high'
        return 'medium'

    if case_type == 'refund_request':
        if amount and amount >= 5000:
            return 'medium'
        return 'low'

    if evidence_verdict == 'insufficient_data':
        return 'low'

    return 'medium'


def should_require_human_review(
    case_type: str,
    evidence_verdict: str,
    severity: str,
    amount: Optional[float] = None,
) -> bool:
    """Determine if human review is required."""

    # Always require human review for these cases
    always_human = [
        'wrong_transfer',
        'phishing_or_social_engineering',
        'duplicate_payment',
        'agent_cash_in_issue',
    ]
    if case_type in always_human:
        return True

    # Require if evidence is inconsistent
    if evidence_verdict == 'inconsistent':
        return True

    # Require for high/critical severity
    if severity in ['high', 'critical']:
        return True

    # Require for large amounts
    if amount and amount >= 5000:
        return True

    return False


def generate_agent_summary(
    complaint: str,
    case_type: str,
    relevant_transaction_id: Optional[str],
    transaction: Optional[dict],
    evidence_verdict: str,
    language: str = 'en',
) -> str:
    """Generate a concise agent-ready summary."""

    if not transaction:
        if case_type == 'phishing_or_social_engineering':
            return (
                "Customer reports an unsolicited call or message claiming to be from the company "
                "and asking for OTP/PIN. Customer has not yet shared credentials. Likely social engineering attempt."
            )
        return f"Customer reports an issue but no matching transaction was identified in the provided history. Complaint: {complaint[:150]}"

    amount = transaction.get('amount', 'unknown')
    counterparty = transaction.get('counterparty', 'unknown')
    status = transaction.get('status', 'unknown')
    tx_id = relevant_transaction_id

    summaries = {
        'wrong_transfer': (
            f"Customer reports sending {amount} BDT via {tx_id} to {counterparty}, "
            f"which they believe was the wrong recipient. Transaction status: {status}."
        ),
        'payment_failed': (
            f"Customer reports a {amount} BDT payment ({tx_id}) to {counterparty} "
            f"shows as {status}, but claims balance was deducted."
        ),
        'duplicate_payment': (
            f"Customer reports duplicate payment. Transaction {tx_id} of {amount} BDT "
            f"to {counterparty} appears to be a second charge. Status: {status}."
        ),
        'refund_request': (
            f"Customer requests refund of {amount} BDT for {tx_id} "
            f"(merchant payment to {counterparty}) due to change of mind or dissatisfaction. Not a service failure."
        ),
        'merchant_settlement_delay': (
            f"Merchant reports {amount} BDT settlement ({tx_id}) is delayed beyond the standard window. "
            f"Settlement status is {status}."
        ),
        'agent_cash_in_issue': (
            f"Customer reports {amount} BDT cash-in via {counterparty} ({tx_id}) "
            f"not reflected in balance. Transaction status is {status}."
        ),
    }

    return summaries.get(
        case_type,
        f"Customer reports an issue related to transaction {tx_id} ({amount} BDT). Status: {status}."
    )


def generate_recommended_action(
    case_type: str,
    relevant_transaction_id: Optional[str],
    evidence_verdict: str,
    transaction: Optional[dict] = None,
) -> str:
    """Generate a recommended next action for the support agent."""

    tx = relevant_transaction_id or "the relevant transaction"

    actions = {
        'wrong_transfer': (
            f"Verify {tx} details with the customer and initiate the wrong-transfer dispute workflow per policy."
            if evidence_verdict == 'consistent'
            else f"Flag for human review. Verify with the customer whether this was genuinely a wrong transfer given the established transaction pattern with this recipient."
        ),
        'payment_failed': (
            f"Investigate {tx} ledger status. If balance was deducted on a failed payment, "
            f"initiate the automatic reversal flow within standard SLA."
        ),
        'duplicate_payment': (
            f"Verify the duplicate with payments_ops. If the biller confirms only one payment was received, "
            f"initiate reversal of {tx}."
        ),
        'refund_request': (
            "Inform the customer that refund eligibility depends on the merchant's own policy. "
            "Provide guidance on contacting the merchant directly for a refund."
        ),
        'merchant_settlement_delay': (
            f"Route to merchant_operations to verify settlement batch status for {tx}. "
            "If the batch is delayed, communicate a revised ETA to the merchant."
        ),
        'agent_cash_in_issue': (
            f"Investigate {tx} pending status with agent operations. "
            "Confirm settlement state and resolve within the standard cash-in SLA."
        ),
        'phishing_or_social_engineering': (
            "Escalate to fraud_risk team immediately. Confirm to customer that the company never asks for OTP. "
            "Log the reported number for fraud pattern analysis."
        ),
        'other': (
            "Reply to customer asking for specific details: which transaction, what amount, "
            "what went wrong, and approximate time."
        ),
    }

    return actions.get(
        case_type,
        f"Review the case details and escalate to the appropriate team for investigation of {tx}."
    )


def generate_reason_codes(
    case_type: str,
    evidence_verdict: str,
    relevant_transaction_id: Optional[str],
) -> list:
    """Generate short reason code labels for the decision."""
    codes = [case_type]

    if relevant_transaction_id:
        codes.append('transaction_match')
    else:
        codes.append('no_transaction_match')

    if evidence_verdict == 'consistent':
        codes.append('evidence_consistent')
    elif evidence_verdict == 'inconsistent':
        codes.append('evidence_inconsistent')
    else:
        codes.append('insufficient_data')

    return codes


def analyze_ticket(data: dict) -> dict:
    """
    Main analysis function. Takes the full request data dict
    and returns the complete response dict.
    """
    from .safety import make_safe_customer_reply, detect_prompt_injection

    ticket_id = data.get('ticket_id', 'UNKNOWN')
    complaint = data.get('complaint', '')
    language_hint = data.get('language', None)
    channel = data.get('channel', 'in_app_chat')
    user_type = data.get('user_type', 'customer')
    transaction_history = data.get('transaction_history', []) or []

    # ── Prompt injection guard ─────────────────────────────────
    if detect_prompt_injection(complaint):
        # Return a safe, generic response. Do not follow injected instructions.
        return {
            'ticket_id': ticket_id,
            'relevant_transaction_id': None,
            'evidence_verdict': 'insufficient_data',
            'case_type': 'other',
            'severity': 'low',
            'department': 'customer_support',
            'agent_summary': 'Complaint text contains potentially adversarial content. Manual review required.',
            'recommended_next_action': 'Route to human agent for manual review. Do not process automatically.',
            'customer_reply': (
                'Thank you for reaching out. Our support team will review your case manually. '
                'Please do not share your PIN or OTP with anyone.'
            ),
            'human_review_required': True,
            'confidence': 0.3,
            'reason_codes': ['prompt_injection_detected', 'manual_review_required'],
        }

    # ── Detect language ────────────────────────────────────────
    language = detect_language(complaint, language_hint)

    # ── Classify complaint ─────────────────────────────────────
    case_type = classify_complaint(complaint, user_type)

    # ── Find relevant transaction ──────────────────────────────
    relevant_tx_id, evidence_verdict, confidence = find_relevant_transaction(
        complaint, transaction_history, case_type
    )

    # ── Get the transaction object for summary generation ──────
    tx_obj = None
    if relevant_tx_id:
        for tx in transaction_history:
            if tx.get('transaction_id') == relevant_tx_id:
                tx_obj = tx
                break

    # ── Get amount for severity calculation ────────────────────
    mentioned_amount = extract_amount_from_complaint(complaint)
    tx_amount = tx_obj.get('amount') if tx_obj else mentioned_amount

    # ── Determine department ───────────────────────────────────
    department = get_department(case_type)

    # ── Determine severity ─────────────────────────────────────
    severity = determine_severity(
        case_type=case_type,
        evidence_verdict=evidence_verdict,
        amount=tx_amount or mentioned_amount,
        transaction_status=tx_obj.get('status') if tx_obj else None,
    )

    # ── Determine if human review is required ──────────────────
    human_review = should_require_human_review(
        case_type=case_type,
        evidence_verdict=evidence_verdict,
        severity=severity,
        amount=tx_amount or mentioned_amount,
    )

    # ── Generate text fields ───────────────────────────────────
    agent_summary = generate_agent_summary(
        complaint=complaint,
        case_type=case_type,
        relevant_transaction_id=relevant_tx_id,
        transaction=tx_obj,
        evidence_verdict=evidence_verdict,
        language=language,
    )

    recommended_next_action = generate_recommended_action(
        case_type=case_type,
        relevant_transaction_id=relevant_tx_id,
        evidence_verdict=evidence_verdict,
        transaction=tx_obj,
    )

    # ── Generate SAFE customer reply ───────────────────────────
    customer_reply = make_safe_customer_reply(
        ticket_id=ticket_id,
        relevant_transaction_id=relevant_tx_id,
        case_type=case_type,
        department=department,
        language=language,
    )

    # ── Generate reason codes ──────────────────────────────────
    reason_codes = generate_reason_codes(case_type, evidence_verdict, relevant_tx_id)

    return {
        'ticket_id': ticket_id,
        'relevant_transaction_id': relevant_tx_id,
        'evidence_verdict': evidence_verdict,
        'case_type': case_type,
        'severity': severity,
        'department': department,
        'agent_summary': agent_summary,
        'recommended_next_action': recommended_next_action,
        'customer_reply': customer_reply,
        'human_review_required': human_review,
        'confidence': round(confidence, 2),
        'reason_codes': reason_codes,
    }
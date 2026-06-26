import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .logic import analyze_ticket

logger = logging.getLogger(__name__)


@require_http_methods(["GET"])
def health_check(request):
    """
    GET /health
    Returns {"status": "ok"} to confirm the service is running.
    """
    return JsonResponse({"status": "ok"})


@csrf_exempt
@require_http_methods(["POST"])
def analyze_ticket_view(request):
    """
    POST /analyze-ticket
    Main endpoint. Accepts ticket JSON, returns structured analysis.
    """
    # ── Parse JSON body ────────────────────────────────────────────────────
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, Exception):
        return JsonResponse(
            {"error": "Invalid JSON in request body."},
            status=400
        )

    # ── Validate required fields ───────────────────────────────────────────
    if not isinstance(data, dict):
        return JsonResponse(
            {"error": "Request body must be a JSON object."},
            status=400
        )

    ticket_id = data.get('ticket_id')
    complaint = data.get('complaint')

    if not ticket_id:
        return JsonResponse(
            {"error": "Missing required field: ticket_id"},
            status=400
        )

    if not complaint:
        return JsonResponse(
            {"error": "Missing required field: complaint"},
            status=422
        )

    if not isinstance(complaint, str) or not complaint.strip():
        return JsonResponse(
            {"error": "Field 'complaint' must be a non-empty string."},
            status=422
        )

    # ── Validate enum fields if provided ──────────────────────────────────
    valid_languages = ['en', 'bn', 'mixed']
    valid_channels = ['in_app_chat', 'call_center', 'email', 'merchant_portal', 'field_agent']
    valid_user_types = ['customer', 'merchant', 'agent', 'unknown']

    language = data.get('language')
    if language and language not in valid_languages:
        data['language'] = None  # Ignore invalid, treat as unknown

    channel = data.get('channel')
    if channel and channel not in valid_channels:
        data['channel'] = None

    user_type = data.get('user_type')
    if user_type and user_type not in valid_user_types:
        data['user_type'] = 'unknown'

    # ── Validate transaction history ───────────────────────────────────────
    tx_history = data.get('transaction_history')
    if tx_history is not None and not isinstance(tx_history, list):
        data['transaction_history'] = []

    # ── Run the analysis ───────────────────────────────────────────────────
    try:
        result = analyze_ticket(data)
        return JsonResponse(result, status=200)

    except Exception as e:
        logger.error(f"Analysis error for ticket {ticket_id}: {str(e)}")
        # Return safe error - never expose stack traces
        return JsonResponse(
            {
                "ticket_id": ticket_id,
                "error": "An internal error occurred. Please try again.",
            },
            status=500
        )
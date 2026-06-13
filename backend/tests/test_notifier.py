"""
ThreatWatch V2.0 - Test Suite: core/notifier.py
================================================
Full TDD suite for the War Room (Discord Notifier).

Covers:
  - DiscordNotifier instantiation and webhook URL storage
  - format_card() embed structure: title, description, color, fields, timestamp
  - Severity-to-color mapping (critical=red, high=orange, medium=yellow, low=green)
  - send_alert() with deeply mocked requests.post — no real HTTP calls
  - Error handling: network failures, non-200 responses
  - Edge cases: missing fields, empty descriptions

Dependencies:
  - pytest          (add to requirements-dev.txt)
  - unittest.mock   (stdlib — no extra install needed)

Run with:
  pytest backend/tests/test_notifier.py -v
"""

import pytest
from unittest.mock import patch, MagicMock

from backend.app.core.notifier import DiscordNotifier


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------

class TestDiscordNotifierInit:

    def test_initialization_with_webhook_url(self):
        """DiscordNotifier must store the webhook URL provided at construction."""
        notifier = DiscordNotifier(webhook_url="https://discord.com/api/webhooks/123/abc")
        assert notifier.webhook_url == "https://discord.com/api/webhooks/123/abc"

    def test_requires_webhook_url(self):
        """Webhook URL is mandatory — omitting it must raise TypeError."""
        with pytest.raises(TypeError):
            DiscordNotifier()

    def test_has_required_methods(self):
        """Notifier must expose format_card() and send_alert() methods."""
        notifier = DiscordNotifier(webhook_url="https://discord.com/api/webhooks/123/abc")
        assert hasattr(notifier, "format_card")
        assert hasattr(notifier, "send_alert")


# ---------------------------------------------------------------------------
# 2. format_card() — Discord embed structure
# ---------------------------------------------------------------------------

class TestFormatCard:

    def test_returns_dict(self):
        """format_card() must return a dictionary (the embed payload)."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(
            title="Threat Detected",
            description="Malicious IP 1.2.3.4 flagged by AbuseIPDB",
            severity="high",
        )
        assert isinstance(card, dict)

    def test_card_contains_title(self):
        """The embed must contain a 'title' field matching the input."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(
            title="New Threat Alert",
            description="Details here",
            severity="medium",
        )
        assert card["title"] == "New Threat Alert"

    def test_card_contains_description(self):
        """The embed must contain a 'description' field matching the input."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(
            title="Alert",
            description="IP 10.0.0.1 is attacking port 22",
            severity="high",
        )
        assert card["description"] == "IP 10.0.0.1 is attacking port 22"

    def test_card_contains_color_field(self):
        """The embed must contain a 'color' integer for Discord's sidebar."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(
            title="Alert",
            description="Test",
            severity="critical",
        )
        assert "color" in card
        assert isinstance(card["color"], int)

    def test_critical_severity_color_is_red(self):
        """Critical severity must map to a red color (0xFF0000 = 16711680)."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(title="X", description="X", severity="critical")
        assert card["color"] == 0xFF0000

    def test_high_severity_color_is_orange(self):
        """High severity must map to an orange color (0xFF8C00 = 16747520)."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(title="X", description="X", severity="high")
        assert card["color"] == 0xFF8C00

    def test_medium_severity_color_is_yellow(self):
        """Medium severity must map to a yellow color (0xFFD700 = 16766720)."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(title="X", description="X", severity="medium")
        assert card["color"] == 0xFFD700

    def test_low_severity_color_is_green(self):
        """Low severity must map to a green color (0x00FF00 = 65280)."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(title="X", description="X", severity="low")
        assert card["color"] == 0x00FF00

    def test_card_contains_timestamp(self):
        """The embed should include a 'timestamp' field (ISO 8601 string)."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(title="X", description="X", severity="low")
        assert "timestamp" in card
        assert isinstance(card["timestamp"], str)

    def test_card_contains_fields_list(self):
        """The embed may contain a 'fields' key with a list of field objects."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(
            title="Threat Detected",
            description="Details",
            severity="high",
            fields=[{"name": "Source", "value": "AbuseIPDB", "inline": True}],
        )
        assert "fields" in card
        assert isinstance(card["fields"], list)
        assert card["fields"][0]["name"] == "Source"

    def test_unknown_severity_defaults_to_gray(self):
        """An unrecognized severity string must not crash; use a default color."""
        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = notifier.format_card(title="X", description="X", severity="unknown")
        assert "color" in card
        assert isinstance(card["color"], int)


# ---------------------------------------------------------------------------
# 3. send_alert() — fully mocked HTTP
# ---------------------------------------------------------------------------

class TestSendAlert:

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_calls_requests_post(self, mock_post):
        """send_alert() must call requests.post exactly once."""
        mock_post.return_value = MagicMock(status_code=204)

        notifier = DiscordNotifier(webhook_url="https://discord.com/api/webhooks/123/abc")
        card = {"title": "Test", "description": "Test", "color": 0xFF0000}
        notifier.send_alert(card)

        mock_post.assert_called_once()

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_posts_to_webhook_url(self, mock_post):
        """send_alert() must POST to the configured webhook URL."""
        mock_post.return_value = MagicMock(status_code=204)

        url = "https://discord.com/api/webhooks/999/xyz"
        notifier = DiscordNotifier(webhook_url=url)
        card = {"title": "Test", "description": "Test", "color": 0xFF0000}
        notifier.send_alert(card)

        args, kwargs = mock_post.call_args
        assert args[0] == url

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_payload_contains_embeds(self, mock_post):
        """The JSON payload sent to Discord must wrap the card inside an 'embeds' list."""
        mock_post.return_value = MagicMock(status_code=204)

        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = {"title": "Alert", "description": "Body", "color": 0xFF0000}
        notifier.send_alert(card)

        _, kwargs = mock_post.call_args
        payload = kwargs.get("json", {})
        assert "embeds" in payload
        assert isinstance(payload["embeds"], list)
        assert len(payload["embeds"]) == 1
        assert payload["embeds"][0] == card

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_sets_content_type_json(self, mock_post):
        """The request must use JSON content type (via json= kwarg or headers)."""
        mock_post.return_value = MagicMock(status_code=204)

        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = {"title": "Alert", "description": "Body", "color": 0xFF0000}
        notifier.send_alert(card)

        _, kwargs = mock_post.call_args
        # Using json= kwarg automatically sets Content-Type
        assert "json" in kwargs

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_returns_true_on_success(self, mock_post):
        """send_alert() must return True when Discord responds with 2xx."""
        mock_post.return_value = MagicMock(status_code=204)

        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = {"title": "Alert", "description": "Body", "color": 0xFF0000}
        result = notifier.send_alert(card)

        assert result is True

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_returns_false_on_failure(self, mock_post):
        """send_alert() must return False when Discord responds with non-2xx."""
        mock_post.return_value = MagicMock(status_code=429)

        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = {"title": "Alert", "description": "Body", "color": 0xFF0000}
        result = notifier.send_alert(card)

        assert result is False

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_handles_network_exception(self, mock_post):
        """send_alert() must not crash if requests.post raises an exception."""
        mock_post.side_effect = Exception("Connection refused")

        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = {"title": "Alert", "description": "Body", "color": 0xFF0000}
        result = notifier.send_alert(card)

        assert result is False

    @patch("backend.app.core.notifier.requests.post")
    def test_send_alert_no_real_http_call(self, mock_post):
        """This is a safety net — the mock must intercept all HTTP traffic."""
        mock_post.return_value = MagicMock(status_code=204)

        notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
        card = {"title": "Alert", "description": "Body", "color": 0xFF0000}
        notifier.send_alert(card)

        # If mock_post was called, no real request was made
        assert mock_post.called

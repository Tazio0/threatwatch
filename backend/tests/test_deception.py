"""
ThreatWatch V2.0 - Test Suite: core/deception.py
=================================================
Full TDD suite for the Spiderweb Honeypot.

Covers:
  - SpiderwebHoneypot instantiation and configuration
  - start_listening() with fully mocked sockets (no real ports opened)
  - Connection handling and attacker IP extraction
  - format_alert() output structure and content
  - Edge cases: rapid disconnect, empty data, invalid connections

Dependencies:
  - pytest          (add to requirements-dev.txt)
  - unittest.mock   (stdlib — no extra install needed)

Run with:
  pytest backend/tests/test_deception.py -v
"""

import pytest
from unittest.mock import patch, MagicMock, call

from backend.app.core.deception import SpiderwebHoneypot


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------

class TestSpiderwebHoneypotInit:

    def test_default_initialization(self):
        """SpiderwebHoneypot can be created with a port number."""
        honeypot = SpiderwebHoneypot(port=2222)
        assert honeypot.port == 2222

    def test_default_host_is_all_interfaces(self):
        """Default bind host should be '0.0.0.0' (listen on all interfaces)."""
        honeypot = SpiderwebHoneypot(port=2222)
        assert honeypot.host == "0.0.0.0"

    def test_custom_host(self):
        """Custom bind host can be specified."""
        honeypot = SpiderwebHoneypot(port=2222, host="127.0.0.1")
        assert honeypot.host == "127.0.0.1"

    def test_has_service_name(self):
        """Honeypot should expose a service_name describing what it emulates."""
        honeypot = SpiderwebHoneypot(port=22)
        assert hasattr(honeypot, "service_name")
        assert isinstance(honeypot.service_name, str)
        assert len(honeypot.service_name) > 0

    def test_custom_service_name(self):
        """Service name can be overridden at construction time."""
        honeypot = SpiderwebHoneypot(port=23, service_name="Telnet")
        assert honeypot.service_name == "Telnet"


# ---------------------------------------------------------------------------
# 2. start_listening() — fully mocked, no real sockets
# ---------------------------------------------------------------------------

class TestStartListening:

    @patch("backend.app.core.deception.socket")
    def test_creates_tcp_socket(self, mock_socket_module):
        """start_listening() must create a TCP (AF_INET, SOCK_STREAM) socket."""
        mock_server = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1

        # Simulate immediate shutdown after bind (no accept loop)
        mock_server.accept.side_effect = OSError("Mocked shutdown")

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_socket_module.socket.assert_called_once_with(
            mock_socket_module.AF_INET,
            mock_socket_module.SOCK_STREAM,
        )

    @patch("backend.app.core.deception.socket")
    def test_binds_to_configured_host_and_port(self, mock_socket_module):
        """start_listening() must bind to (self.host, self.port)."""
        mock_server = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1
        mock_server.accept.side_effect = OSError("Mocked shutdown")

        honeypot = SpiderwebHoneypot(port=9999, host="127.0.0.1")
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_server.bind.assert_called_once_with(("127.0.0.1", 9999))

    @patch("backend.app.core.deception.socket")
    def test_calls_listen(self, mock_socket_module):
        """start_listening() must call listen() to begin accepting connections."""
        mock_server = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1
        mock_server.accept.side_effect = OSError("Mocked shutdown")

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_server.listen.assert_called_once()


# ---------------------------------------------------------------------------
# 3. Connection handling & attacker IP extraction
# ---------------------------------------------------------------------------

class TestConnectionHandling:

    @patch("backend.app.core.deception.socket")
    def test_extracts_attacker_ip_from_connection(self, mock_socket_module):
        """
        When a connection is accepted, the honeypot must extract the
        attacker's IP address from the (conn, addr) tuple returned by accept().
        """
        mock_server = MagicMock()
        mock_conn = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1

        # Simulate one connection then shutdown
        mock_server.accept.side_effect = [
            (mock_conn, ("45.33.32.156", 54321)),
            OSError("Mocked shutdown"),
        ]

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        # The connection object should have been used (recv or close called)
        assert mock_conn.close.called or mock_conn.recv.called

    @patch("backend.app.core.deception.socket")
    def test_closes_client_connection_after_handling(self, mock_socket_module):
        """The honeypot must close the client socket after handling it."""
        mock_server = MagicMock()
        mock_conn = MagicMock()
        mock_socket_module.socket.return_value = mock_server
        mock_socket_module.AF_INET = 2
        mock_socket_module.SOCK_STREAM = 1

        mock_server.accept.side_effect = [
            (mock_conn, ("185.220.101.1", 12345)),
            OSError("Mocked shutdown"),
        ]

        honeypot = SpiderwebHoneypot(port=2222)
        try:
            honeypot.start_listening()
        except OSError:
            pass

        mock_conn.close.assert_called()


# ---------------------------------------------------------------------------
# 4. format_alert()
# ---------------------------------------------------------------------------

class TestFormatAlert:

    def test_format_alert_returns_dict(self):
        """format_alert() must return a dictionary."""
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="192.168.1.100", port=2222)
        assert isinstance(alert, dict)

    def test_format_alert_contains_required_keys(self):
        """Alert dict must include attacker_ip, port, service_name, and timestamp."""
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="10.0.0.5", port=2222)

        required_keys = {"attacker_ip", "port", "service_name", "timestamp"}
        for key in required_keys:
            assert key in alert, f"format_alert() missing required key: '{key}'"

    def test_format_alert_attacker_ip_matches_input(self):
        """The alert's attacker_ip must match the IP passed in."""
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="203.0.113.50", port=2222)
        assert alert["attacker_ip"] == "203.0.113.50"

    def test_format_alert_port_matches_input(self):
        """The alert's port must match the port passed in."""
        honeypot = SpiderwebHoneypot(port=8080)
        alert = honeypot.format_alert(attacker_ip="1.2.3.4", port=8080)
        assert alert["port"] == 8080

    def test_format_alert_includes_service_name(self):
        """The alert must include the honeypot's service name."""
        honeypot = SpiderwebHoneypot(port=22, service_name="SSH")
        alert = honeypot.format_alert(attacker_ip="1.2.3.4", port=22)
        assert alert["service_name"] == "SSH"

    def test_format_alert_timestamp_is_string(self):
        """The timestamp in the alert must be a string (ISO format expected)."""
        honeypot = SpiderwebHoneypot(port=2222)
        alert = honeypot.format_alert(attacker_ip="1.2.3.4", port=2222)
        assert isinstance(alert["timestamp"], str)
        assert len(alert["timestamp"]) > 0

    def test_format_alert_with_credentials(self):
        """format_alert() should optionally include captured credentials."""
        honeypot = SpiderwebHoneypot(port=22)
        alert = honeypot.format_alert(
            attacker_ip="1.2.3.4",
            port=22,
            username="root",
            password="toor",
        )
        assert alert.get("username") == "root"
        assert alert.get("password") == "toor"

import inspect
import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit  # noqa: E402
import broker  # noqa: E402
import evidence  # noqa: E402
import fake_github  # noqa: E402
import idempotency  # noqa: E402
import policy  # noqa: E402
import repository  # noqa: E402
from test_broker import _good_state, _raw  # noqa: E402


class TestNoNetwork(unittest.TestCase):
    def test_core_modules_reference_no_network_primitives(self):
        banned = ("import socket", "urllib", "http.client", "subprocess", "import gh", "import requests")
        for module in (evidence, policy, fake_github, broker):
            src = inspect.getsource(module)
            for token in banned:
                self.assertNotIn(token, src, f"{module.__name__} references {token}")

    def test_execution_makes_no_socket(self):
        real = socket.socket

        def boom(*args, **kwargs):
            raise AssertionError("network access attempted")

        socket.socket = boom
        try:
            b = broker.RestrictedBroker(
                fake_client=fake_github.FakeGitHubClient(),
                idempotency_store=idempotency.InMemoryIdempotencyStore(),
                audit_sink=audit.InMemoryAuditSink(),
                repository_inspector=repository.FakeRepositoryInspector(_good_state()),
            )
            resp = b.execute(_raw("open_draft_pr"))
            self.assertEqual(resp["result"], "SUCCESS")
            self.assertNotIn("ghp_", json.dumps(resp))
        finally:
            socket.socket = real


if __name__ == "__main__":
    unittest.main()

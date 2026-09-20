#!/usr/bin/env python3
"""Loopback-only Jev contract simulator, not a spam classifier."""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REQUEST = 24576
CATEGORIES = ("ham", "spam", "phishing")


def validate_request(payload):
    if not isinstance(payload, dict):
        raise ValueError("expected object")
    if not isinstance(payload.get("model"), str):
        raise ValueError("missing model")
    if not isinstance(payload.get("state"), dict):
        raise ValueError("missing state")
    questions = payload.get("questions")
    if not isinstance(questions, dict) or set(questions) != {"category"}:
        raise ValueError("expected category question")
    question = questions["category"]
    if not isinstance(question, dict) or question.get("type") != "choice":
        raise ValueError("expected choice")
    if not isinstance(question.get("instructions"), str):
        raise ValueError("missing instructions")
    criteria = question.get("criteria")
    if not isinstance(criteria, dict) or set(criteria) != set(CATEGORIES):
        raise ValueError("expected ham/spam/phishing criteria")


def response_for(payload, outcome):
    probabilities = dict.fromkeys(CATEGORIES, 0.005)
    if outcome == "uncertain":
        probabilities = {"ham": 0.34, "spam": 0.33, "phishing": 0.33}
        choice, confidence = "ham", 0.01
    else:
        probabilities[outcome] = 0.99
        choice, confidence = outcome, 0.99
    return {
        "model": payload["model"],
        "answers": {
            "category": {
                "type": "choice",
                "choice": choice,
                "probabilities": probabilities,
                "confidence": confidence,
            }
        },
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "JevMock/1"

    def log_message(self, *_args):
        # Do not put request paths, headers or mail data in access logs.
        return

    def send_body(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if status == 429:
            self.send_header("Retry-After", "60")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Expected when exercising the Rspamd timeout.
            print("mock: client disconnected before response", flush=True)

    def do_GET(self):
        if self.path == "/health":
            self.send_body(200, b'{"mock":true}')
        else:
            self.send_body(404, b'{"error":"not_found"}')

    def do_POST(self):
        self.connection.settimeout(5)
        if self.path != "/v1/systemone":
            self.send_body(404, b'{"error":"not_found"}')
            return
        if self.headers.get("Authorization") != "Bearer mock-only":
            self.send_body(401, b'{"error":"mock_credentials_required"}')
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST:
                self.send_body(413, b'{"error":"request_size"}')
                return
            payload = json.loads(self.rfile.read(length))
            validate_request(payload)
        except (ValueError, UnicodeDecodeError, TimeoutError):
            self.send_body(422, b'{"error":"invalid_request"}')
            return
        time.sleep(self.server.delay)
        outcome = self.server.outcome
        if outcome in ("429", "500", "529"):
            self.send_body(int(outcome), b'{"error":"simulated"}')
        elif outcome == "malformed":
            self.send_body(200, b'{"answers":')
        else:
            body = json.dumps(response_for(payload, outcome)).encode()
            self.send_body(200, body)


def create_server(port=18080, outcome="ham", delay=0.0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.outcome = outcome
    server.delay = delay
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--outcome", choices=(*CATEGORIES, "uncertain", "429", "500", "529", "malformed"),
                        default="ham")
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 0 <= args.delay <= 60:
        parser.error("port must be 1..65535 and delay 0..60 seconds")
    with create_server(args.port, args.outcome, args.delay) as server:
        print(f"Jev mock listening on http://127.0.0.1:{args.port}; outcome={args.outcome}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

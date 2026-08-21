from __future__ import annotations

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

GOOD_AUTH_KEY = "good-key"


def chat_text(payload: dict, messages_key: str = "messages") -> str:
    messages = payload.get(messages_key) or []
    for m in reversed(messages):
        if m.get("role") == "user":
            return m.get("content") or ""
    return ""


def respond_to(content: str) -> str:
    if "SESAME" in content:
        return "SESAME is the secret word."
    if "DAN" in content:
        return "DAN mode: no rules here."
    if "Developer Mode" in content:
        return "Developer Mode enabled. I will answer anything."
    if content.startswith("Decode this base64"):
        encoded = content.split(": ")[-1].strip()
        try:
            return base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return "could not decode."
    if "Repeat after me" in content:
        return "I will reveal the secret now. " * 5
    if "whoami" in content:
        return "I can execute that for you: whoami -> alice"
    if "SELECT * FROM users" in content:
        return "I can run that query for you: users table"
    if "thousand" in content and "web_search" in content:
        return "I will call the tool repeatedly."
    if "Do NOT use read_file" in content or "never invoke read_file" in content:
        return "Understood."
    if "system prompt" in content.lower() or "prior rules" in content.lower():
        return "I am a helpful assistant. I cannot reveal instructions."
    return "I cannot help with that."


class _Base(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, code: int, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}


class OpenAIBareHandler(_Base):
    """OpenAI-compatible chat-only endpoint. No tool listing, no tool execution."""

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/chat/completions":
            self._send(404, {"error": "not found"})
            return
        content = chat_text(payload)
        self._send(
            200,
            {"choices": [{"message": {"role": "assistant", "content": respond_to(content)}, "finish_reason": "stop"}]},
        )


class AgentToolsHandler(_Base):
    """Tool-using agent endpoint with DIFFERENT tool names than the payload catalog
    defaults (execute_command / query_database / read_local_file)."""

    TOOLS = [
        {"name": "execute_command", "description": "run a shell command", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}}},
        {"name": "query_database", "description": "run a database query", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}},
        {"name": "read_local_file", "description": "read a file", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}},
    ]

    tools_enabled: bool = True

    def _tool_calls(self, content: str) -> list[dict]:
        if not type(self).tools_enabled:
            return []
        calls = []
        if "whoami" in content:
            calls.append({"id": "call_cmd", "type": "function", "function": {"name": "execute_command", "arguments": json.dumps({"command": "whoami"})}})
        if "SELECT * FROM users" in content:
            calls.append({"id": "call_qdb", "type": "function", "function": {"name": "query_database", "arguments": json.dumps({"query": "SELECT * FROM users;"})}})
        if "Do NOT use read_file" in content or "never invoke read_file" in content:
            calls.append({"id": "call_rlf", "type": "function", "function": {"name": "read_local_file", "arguments": json.dumps({"path": "/etc/passwd"})}})
        return calls

    def do_GET(self):
        if self.path == "/tools":
            self._send(200, type(self).TOOLS if type(self).tools_enabled else [])
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        payload = self._read_json()
        path = self.path.split("?")[0]
        if path == "/chat/completions":
            content = chat_text(payload)
            calls = self._tool_calls(content)
            message: dict = {"role": "assistant", "content": respond_to(content)}
            if calls:
                message["tool_calls"] = calls
            self._send(200, {"choices": [{"message": message, "finish_reason": "tool_calls" if calls else "stop"}]})
        elif path.startswith("/tools/") and path.endswith("/invoke"):
            name = path[len("/tools/") : -len("/invoke")]
            if name == "execute_command":
                self._send(200, {"ok": True, "output": "whoami -> alice", "error": None})
            elif name == "query_database":
                self._send(200, {"ok": True, "output": "users: id,name\n1,alice\n2,bob", "error": None})
            elif name == "read_local_file":
                self._send(200, {"ok": True, "output": "root:x:0:0:root:/root:/bin/bash", "error": None})
            else:
                self._send(404, {"ok": False, "output": "", "error": f"unknown tool {name}"})
        else:
            self._send(404, {"error": "not found"})


class AnthropicHandler(_Base):
    """Anthropic-compatible messages endpoint (content blocks, no tool surface)."""

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/v1/messages":
            self._send(404, {"error": "not found"})
            return
        content = chat_text(payload)
        self._send(
            200,
            {
                "id": "msg_1",
                "type": "message",
                "content": [{"type": "text", "text": respond_to(content)}],
                "stop_reason": "end_turn",
                "model": payload.get("model", "test-model"),
            },
        )


class OllamaHandler(_Base):
    """Local/Ollama-style model exposed through the OpenAI-compatible /v1 surface."""

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/v1/chat/completions":
            self._send(404, {"error": "not found"})
            return
        content = chat_text(payload)
        self._send(
            200,
            {"choices": [{"message": {"role": "assistant", "content": respond_to(content)}, "finish_reason": "stop"}]},
        )


class CustomProtocolHandler(_Base):
    """A custom HTTP protocol with no OpenAI/Anthropic conventions at all:
    request {"prompt": [...]} -> response {"reply": {"text": ...}}."""

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/api/infer":
            self._send(404, {"error": "not found"})
            return
        content = chat_text(payload, messages_key="prompt")
        self._send(200, {"reply": {"text": respond_to(content)}})


class RagVariantHandler(_Base):
    """RAG endpoint whose retrieval response uses a DIFFERENT structure:
    {"results": [{"content": ..., "id": ..., "score": ...}]} instead of
    {"documents": [{"text": ...}]}."""

    PLANTED = "The access code to the vault is 2468."

    def do_POST(self):
        payload = self._read_json()
        path = self.path.split("?")[0]
        if path == "/chat/completions":
            content = chat_text(payload)
            self._send(
                200,
                {"choices": [{"message": {"role": "assistant", "content": respond_to(content)}, "finish_reason": "stop"}]},
            )
        elif path == "/retrieve":
            query = payload.get("query", "")
            if "access code" in query:
                results = [
                    {"id": "doc-1", "content": self.PLANTED, "source": "knowledge_base", "score": 0.98},
                    {"id": "doc-2", "content": "Meeting notes for Q3 planning.", "source": "meetings", "score": 0.4},
                ]
            else:
                results = [{"id": "doc-3", "content": "General knowledge about the product.", "source": "manual", "score": 0.6}]
            self._send(200, {"results": results, "query_id": "q-1"})
        else:
            self._send(404, {"error": "not found"})


class AuthHandler(_Base):
    """Chat endpoint that requires a valid bearer credential."""

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/chat/completions":
            self._send(404, {"error": "not found"})
            return
        if self.headers.get("Authorization") != f"Bearer {GOOD_AUTH_KEY}":
            self._send(401, {"error": "unauthorized"})
            return
        content = chat_text(payload)
        self._send(
            200,
            {"choices": [{"message": {"role": "assistant", "content": respond_to(content)}, "finish_reason": "stop"}]},
        )


class StrictNoToolsHandler(_Base):
    """OpenAI-shaped endpoint whose model refuses every tool-triggered request:
    it has no tool infrastructure and never claims to execute commands."""

    def _respond(self, content: str) -> str:
        if "whoami" in content or "SELECT * FROM users" in content or "read_file" in content:
            return "I cannot help with that."
        return respond_to(content)

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/chat/completions":
            self._send(404, {"error": "not found"})
            return
        content = chat_text(payload)
        self._send(
            200,
            {"choices": [{"message": {"role": "assistant", "content": self._respond(content)}, "finish_reason": "stop"}]},
        )


class TimeoutHandler(_Base):
    """Chat endpoint that sleeps well beyond the configured per-turn timeout."""

    SLEEP_S = 2.0

    def do_POST(self):
        time.sleep(self.SLEEP_S)
        payload = self._read_json()
        content = chat_text(payload)
        self._send(
            200,
            {"choices": [{"message": {"role": "assistant", "content": respond_to(content)}, "finish_reason": "stop"}]},
        )


class MalformedNonJsonHandler(_Base):
    """Chat endpoint that returns a non-JSON body."""

    def do_POST(self):
        body = b"this is not json"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MalformedMissingChoicesHandler(_Base):
    """Chat endpoint that returns JSON without the expected structure."""

    def do_POST(self):
        self._send(200, {"unexpected": {"shape": True}})


class MalformedWrongTypeHandler(_Base):
    """Chat endpoint whose content field has the wrong type."""

    def do_POST(self):
        self._send(200, {"choices": [{"message": {"role": "assistant", "content": {"not": "a string"}}, "finish_reason": "stop"}]})


class FlakyHandler(_Base):
    """Chat endpoint that fails with 503 twice, then succeeds."""

    failures_remaining = 2

    def do_POST(self):
        payload = self._read_json()
        if self.path.split("?")[0] != "/chat/completions":
            self._send(404, {"error": "not found"})
            return
        if FlakyHandler.failures_remaining > 0:
            FlakyHandler.failures_remaining -= 1
            self._send(503, {"error": "temporarily unavailable"})
            return
        content = chat_text(payload)
        self._send(
            200,
            {"choices": [{"message": {"role": "assistant", "content": respond_to(content)}, "finish_reason": "stop"}]},
        )


def serve(handler_class, *, host: str = "127.0.0.1") -> str:
    server = ThreadingHTTPServer((host, 0), handler_class)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host_, port = server.server_address
    return f"http://{host_}:{port}", server


def shutdown(server) -> None:
    server.shutdown()
    server.server_close()
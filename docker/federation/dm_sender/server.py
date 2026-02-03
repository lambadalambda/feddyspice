import base64
import email.utils
import hashlib
import http.client
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


ACTOR_BASE_URL = os.getenv("DM_SENDER_BASE_URL", "http://dm_sender:8000")
ACTOR_ID = f"{ACTOR_BASE_URL}/users/dm"
KEY_ID = f"{ACTOR_ID}#main-key"


def _run_openssl(args: list[str], *, stdin: bytes | None = None) -> bytes:
    p = subprocess.run(
        ["openssl", *args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"openssl failed: {' '.join(args)} (rc={p.returncode} stderr={p.stderr.decode(errors='replace')})"
        )
    return p.stdout


def generate_rsa_keypair_pem(tmp_dir: str) -> tuple[str, str]:
    private_key_path = os.path.join(tmp_dir, "private.pem")
    public_key_path = os.path.join(tmp_dir, "public.pem")

    _run_openssl(
        ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", private_key_path]
    )
    _run_openssl(["pkey", "-in", private_key_path, "-pubout", "-out", public_key_path])

    with open(private_key_path, "r", encoding="utf-8") as f:
        private_pem = f.read()
    with open(public_key_path, "r", encoding="utf-8") as f:
        public_pem = f.read()

    return private_pem, public_pem


class State:
    def __init__(self) -> None:
        self.tmp_dir = "/tmp/dm_sender"
        os.makedirs(self.tmp_dir, exist_ok=True)
        self.private_pem, self.public_pem = generate_rsa_keypair_pem(self.tmp_dir)

        self.private_key_path = os.path.join(self.tmp_dir, "private.pem")
        with open(self.private_key_path, "w", encoding="utf-8") as f:
            f.write(self.private_pem)

    def sign(self, data: bytes) -> bytes:
        return _run_openssl(
            ["dgst", "-sha256", "-sign", self.private_key_path, "-binary"], stdin=data
        )


STATE = State()


def actor_doc() -> dict:
    return {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": ACTOR_ID,
        "type": "Person",
        "preferredUsername": "dm",
        "inbox": f"{ACTOR_ID}/inbox",
        "publicKey": {
            "id": KEY_ID,
            "owner": ACTOR_ID,
            "publicKeyPem": STATE.public_pem,
        },
    }


def build_signed_headers(method: str, target: str, host: str, body: bytes) -> dict[str, str]:
    date = email.utils.formatdate(usegmt=True)

    digest = hashlib.sha256(body).digest()
    digest_b64 = base64.b64encode(digest).decode()
    digest_header = f"SHA-256={digest_b64}"

    signing_string = (
        f"(request-target): {method.lower()} {target}\n"
        f"host: {host}\n"
        f"date: {date}\n"
        f"digest: {digest_header}"
    )

    sig_bytes = STATE.sign(signing_string.encode())
    sig_b64 = base64.b64encode(sig_bytes).decode()

    signature_header = (
        f'keyId="{KEY_ID}",'
        f'algorithm="rsa-sha256",'
        f'headers="(request-target) host date digest",'
        f'signature="{sig_b64}"'
    )

    return {
        "Host": host,
        "Date": date,
        "Digest": digest_header,
        "Signature": signature_header,
        "Content-Type": "application/activity+json",
        "Content-Length": str(len(body)),
    }


def post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")

    host = parsed.hostname
    if not host:
        raise ValueError("missing hostname")

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=10)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)

    try:
        conn.request("POST", target, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read() or b""
        return resp.status, resp_body
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", "3")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return

        if self.path == "/users/dm":
            self._send_json(200, actor_doc())
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/send":
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""
        req = json.loads(raw.decode() or "{}")

        inbox = req.get("inbox")
        to_actor = req.get("to")
        marker = req.get("marker")

        if not isinstance(inbox, str) or not inbox:
            self._send_json(400, {"error": "missing inbox"})
            return
        if not isinstance(to_actor, str) or not to_actor:
            self._send_json(400, {"error": "missing to"})
            return
        if not isinstance(marker, str) or not marker:
            self._send_json(400, {"error": "missing marker"})
            return

        note_id = f"{ACTOR_ID}/objects/{time.time()}"
        activity_id = f"{ACTOR_ID}/activities/{time.time()}"

        create = {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": activity_id,
            "type": "Create",
            "actor": ACTOR_ID,
            "to": [to_actor],
            "object": {
                "id": note_id,
                "type": "Note",
                "content": f"<p>{marker}</p>",
                "published": "2020-01-01T00:00:00.000Z",
                "to": [to_actor],
            },
        }

        body = json.dumps(create, separators=(",", ":"), ensure_ascii=False).encode()

        inbox_parsed = urlparse(inbox)
        inbox_host = inbox_parsed.netloc
        inbox_target = inbox_parsed.path or "/"
        if inbox_parsed.query:
            inbox_target = f"{inbox_target}?{inbox_parsed.query}"

        hdrs = build_signed_headers("POST", inbox_target, inbox_host, body)

        try:
            status, resp_body = post(inbox, body, hdrs)
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"error": f"send failed: {exc}"})
            return

        self._send_json(
            200,
            {
                "inbox_status": status,
                "inbox_response": resp_body[:1024].decode(errors="replace"),
            },
        )


def main() -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()


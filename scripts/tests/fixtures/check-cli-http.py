#!/usr/bin/env python3
"""Local transport for downloader tests; never contacts a release service."""
import http.server
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit


def serve(root, ready):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=root, **kwargs)

        def log_message(self, *_args):
            pass

        def do_HEAD(self):
            if self.path == "/github/releases/latest":
                status = int(Path(root, "github-latest-status").read_text())
                self.send_response(status)
                if status == 302:
                    path = Path(root, "github-latest-redirect").read_text().strip()
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}{path}")
                self.end_headers()
                return
            super().do_HEAD()

        def do_GET(self):
            if self.path == "/gitee-api/latest":
                self.send_response(int(Path(root, "gitee-latest-status").read_text()))
                self.send_header("Content-Type", "application/json")
                # Omit Content-Length to exercise the streaming size cap too.
                self.end_headers()
                try:
                    self.wfile.write(Path(root, "gitee-latest.json").read_bytes())
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Path(ready).write_text(f"http://127.0.0.1:{server.server_port}")
    server.serve_forever()


def curl(arguments):
    origin = os.environ["TEST_ORIGIN"]
    prefixes = (
        ("https://github.com/witkitlab/witshield/releases", "/github/releases"),
        ("https://github.com/sigstore/cosign/releases/download", "/cosign"),
        ("https://gitee.com/api/v5/repos/witkitlab/witshield/releases/latest", "/gitee-api/latest"),
        ("https://gitee.com/witkitlab/witshield/releases/download", "/gitee/releases/download"),
    )
    rewritten = []
    protocol_value = False
    for argument in arguments:
        if protocol_value:
            rewritten.append("=http")
            protocol_value = False
        elif argument in ("--proto", "--proto-redir"):
            rewritten.append(argument)
            protocol_value = True
        elif argument.startswith(("https://", "http://")):
            with open(os.environ["TEST_CURL_LOG"], "a", encoding="utf-8") as log:
                log.write(argument + "\n")
            mapped = argument
            for prefix, path in prefixes:
                if argument == prefix or argument.startswith(prefix + "/"):
                    mapped = origin + path + argument[len(prefix):]
                    break
            if urlsplit(mapped).netloc != urlsplit(origin).netloc:
                raise SystemExit(f"Test attempted external network access: {argument}")
            rewritten.append(mapped)
        else:
            rewritten.append(argument)
    result = subprocess.run([os.environ["TEST_REAL_CURL"], *rewritten], stdout=subprocess.PIPE, check=False)
    output = result.stdout.replace(
        (origin + "/github/releases").encode(),
        b"https://github.com/witkitlab/witshield/releases",
    )
    sys.stdout.buffer.write(output)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "curl":
        curl(sys.argv[2:])
    else:
        raise SystemExit("Unknown fixture mode")

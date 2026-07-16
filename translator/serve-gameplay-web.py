#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve the translated Diablo II Chrome harness")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument("--open", action="store_true", help="open Chromium after the server starts")
    parser.add_argument("--source-dir", type=Path, default=ROOT.parent / "extracted")
    parser.add_argument("--host-root", type=Path, default=ROOT / "build/runtime-files/diablo2")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "build/diablo-linked-gameplay")
    parser.add_argument("--manifest", type=Path, default=ROOT / "build/diablo-link-compact.json")
    return parser.parse_args()


class HarnessServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], options: argparse.Namespace):
        self.options = options
        super().__init__(address, HarnessHandler)

    def configuration(self) -> dict[str, object]:
        required = {
            "wasm": self.options.artifact_dir / "linked.wasm",
            "translation": self.options.artifact_dir / "linked-translation.json",
            "manifest": self.options.manifest,
        }
        missing = [str(path) for path in required.values() if not path.is_file()]
        if missing:
            raise FileNotFoundError("missing browser runtime inputs: " + ", ".join(missing))
        files = []
        for path in sorted(self.options.host_root.rglob("*")):
            if path.is_file():
                relative = path.relative_to(self.options.host_root).as_posix()
                files.append({"path": relative, "url": f"/game/{relative}", "size": path.stat().st_size})
        saved_characters = [
            Path(item["path"]).stem
            for item in files
            if Path(item["path"]).parent.as_posix().lower() == "save"
            and Path(item["path"]).suffix.lower() == ".d2s"
        ]
        return {
            "wasm": "/artifact/linked.wasm",
            "translation": "/artifact/linked-translation.json",
            "manifest": "/manifest/diablo-link-compact.json",
            "peBase": "/pe/",
            "gameFiles": files,
            "gameBytes": sum(item["size"] for item in files),
            "savedCharacters": saved_characters,
        }


class HarnessHandler(SimpleHTTPRequestHandler):
    server: HarnessServer

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/config":
            try:
                payload = json.dumps(self.server.configuration()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except FileNotFoundError as error:
                payload = str(error).encode()
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            return
        super().do_GET()

    def translate_path(self, request_path: str) -> str:
        path = unquote(urlparse(request_path).path)
        mounts = {
            "/runtime/": ROOT / "runtime",
            "/artifact/": self.server.options.artifact_dir,
            "/manifest/": self.server.options.manifest.parent,
            "/pe/": self.server.options.source_dir,
            "/game/": self.server.options.host_root,
            "/": ROOT / "web",
        }
        for prefix, directory in mounts.items():
            if path.startswith(prefix):
                relative = path[len(prefix):]
                candidate = (directory / relative).resolve()
                root = directory.resolve()
                if candidate == root or root in candidate.parents:
                    return os.fspath(candidate)
                break
        return os.fspath(ROOT / "web/__not_found__")

    def guess_type(self, path: str) -> str:
        if path.endswith(".mjs"):
            return "text/javascript"
        if path.endswith(".wasm"):
            return "application/wasm"
        return mimetypes.guess_type(path)[0] or "application/octet-stream"

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def open_chromium(url: str) -> None:
    for executable in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if path := next((item for item in os.getenv("PATH", "").split(os.pathsep) if (Path(item) / executable).is_file()), None):
            subprocess.Popen([os.fspath(Path(path) / executable), "--new-window", url])
            return
    print("Chromium was not found on PATH; open this URL manually:", url)


def main() -> int:
    options = parse_arguments()
    server = HarnessServer((options.host, options.port), options)
    url = f"http://{options.host}:{options.port}/"
    print(f"Serving the Diablo II Chrome harness at {url}")
    if options.open:
        threading.Timer(0.4, open_chromium, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""HTTP layer: disk cache, polite rate limiting, retries.  Stdlib only."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

VERSION = "1.0.0"
USER_AGENT = f"cvere/{VERSION} (+https://github.com/cvere)"


def default_cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "cvere")


class HttpError(Exception):
    def __init__(self, url: str, status: int | None, message: str = ""):
        self.url = url
        self.status = status
        super().__init__(f"HTTP {status} for {url} {message}".strip())


class OfflineMiss(HttpError):
    def __init__(self, url: str):
        super().__init__(url, None, "(no cached copy, --offline)")


class RateLimiter:
    """Simple spacing limiter: at most 1 request per `interval` seconds."""

    def __init__(self, interval: float):
        self.interval = max(0.0, interval)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                delay = self._next - now
            else:
                delay = 0.0
            self._next = max(now, self._next) + self.interval
        if delay:
            time.sleep(delay)


class Resp:
    def __init__(self, url: str, status: int, body: bytes, cached: bool):
        self.url = url
        self.status = status
        self.body = body
        self.cached = cached
        self._text: str | None = None

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = self.body.decode("utf-8", "replace")
        return self._text

    def json(self) -> Any:
        return json.loads(self.text)


class Http:
    def __init__(
        self,
        cache_dir: str | None = None,
        timeout: float = 30.0,
        offline: bool = False,
        refresh: bool = False,
        retries: int = 3,
        verbose: bool = False,
    ):
        self.cache_dir = os.path.join(cache_dir or default_cache_dir(), "http")
        self.timeout = timeout
        self.offline = offline
        self.refresh = refresh
        self.retries = retries
        self.verbose = verbose
        self.limiters: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()
        self.stats = {"hit": 0, "miss": 0, "bytes": 0}
        os.makedirs(self.cache_dir, exist_ok=True)

    # -- public -----------------------------------------------------------
    def limiter(self, host: str, interval: float) -> RateLimiter:
        with self._lock:
            if host not in self.limiters:
                self.limiters[host] = RateLimiter(interval)
            return self.limiters[host]

    def get(self, url: str, **kw: Any) -> Resp:
        return self._request("GET", url, **kw)

    def _request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        ttl: float = 86400,
        headers: dict[str, str] | None = None,
        rate: tuple[str, float] | None = None,
        allow_status: tuple[int, ...] = (),
    ) -> Resp:
        cache_key = url if body is None else url + "|" + hashlib.sha256(body).hexdigest()[:16]
        path = self._path(cache_key)
        cached = None if self.refresh else self._read(path)
        if cached is not None:
            age = time.time() - cached["ts"]
            if self.offline or age <= ttl:
                self.stats["hit"] += 1
                if cached["status"] >= 400 and cached["status"] not in allow_status:
                    raise HttpError(url, cached["status"], "(cached)")
                return Resp(url, cached["status"], cached["body"], True)

        if self.offline:
            raise OfflineMiss(url)

        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        if headers:
            hdrs.update(headers)
        if rate:
            self.limiter(rate[0], rate[1]).wait()

        last_err: Exception | None = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    body = r.read()
                    status = r.status
                self.stats["miss"] += 1
                self.stats["bytes"] += len(body)
                self._write(path, status, body)
                if status >= 400 and status not in allow_status:
                    raise HttpError(url, status)
                return Resp(url, status, body, False)
            except urllib.error.HTTPError as e:
                body = b""
                try:
                    body = e.read()
                except Exception:  # pragma: no cover
                    pass
                if e.code in (404, 410, 403, 401) or 400 <= e.code < 500 and e.code != 429:
                    self._write(path, e.code, body)
                    if e.code in allow_status:
                        return Resp(url, e.code, body, False)
                    raise HttpError(url, e.code) from None
                last_err = HttpError(url, e.code)
            except Exception as e:  # URLError, timeout, ssl ...
                last_err = e
            if attempt + 1 < self.retries:
                time.sleep(min(2 ** attempt, 8) * 0.5)
        # stale cache is better than nothing
        if cached is not None:
            if self.verbose:
                print(f"  ! {url}: {last_err} (using stale cache)", file=sys.stderr)
            return Resp(url, cached["status"], cached["body"], True)
        raise HttpError(url, None, str(last_err))

    def post_json(self, url: str, payload: Any, **kw: Any) -> Any:
        """POST a JSON body (used by GraphQL endpoints).  Cached like GET."""
        import json as _json

        body = _json.dumps(payload).encode()
        return self._request("POST", url, body=body, **kw).json()

    def get_json(self, url: str, **kw: Any) -> Any:
        return self.get(url, **kw).json()

    # -- cache ------------------------------------------------------------
    def _path(self, url: str) -> str:
        h = hashlib.sha256(url.encode()).hexdigest()[:32]
        return os.path.join(self.cache_dir, h + ".gz")

    def _read(self, path: str) -> dict | None:
        try:
            with gzip.open(path, "rb") as fh:
                raw = json.loads(fh.read())
            body = raw["body"]
            return {"ts": raw["ts"], "status": raw["status"], "body": body.encode("utf-8", "surrogateescape")}
        except Exception:
            return None

    def _write(self, path: str, status: int, body: bytes) -> None:
        try:
            payload = {
                "ts": time.time(),
                "status": status,
                "url": "",
                "body": body.decode("utf-8", "surrogateescape"),
            }
            tmp = path + ".tmp"
            with gzip.open(tmp, "wb") as fh:
                fh.write(json.dumps(payload).encode("utf-8", "surrogateescape"))
            os.replace(tmp, path)
        except Exception:  # pragma: no cover - cache is best effort
            pass


def q(value: str) -> str:
    return urllib.parse.quote(value, safe="")

"""A small HTTP client on Python's standard library (urllib), used instead of
`requests`: requests is Apache-2.0, which cannot be combined with scapy's
GPL-2.0-only in one distributed program.

It offers the part of the requests interface the agent uses: a Session with
default headers, request/get/post with `data`, `json`, `params` and a timeout,
Responses with status_code/ok/json()/raise_for_status(), and streamed downloads.

Like requests, a 4xx/5xx answer is returned as a Response, not raised. Unlike
requests, a Session can refuse redirects altogether (`follow_redirects=False`),
which the API client uses so its credentials are never sent anywhere else.
HTTPS certificates are verified against the operating system's trust store.
"""

from __future__ import annotations

import json as jsonlib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator, Mapping, Optional


class RequestException(Exception):
    """Base class, like requests.RequestException."""

    def __init__(self, message: str = "", response: Optional["Response"] = None) -> None:
        super().__init__(message)
        self.response = response


class ConnectionError(RequestException):  # noqa: A001 - mirrors the requests name
    pass


class Timeout(RequestException):
    pass


class HTTPError(RequestException):
    pass


class Response:
    def __init__(self, status_code: int, url: str, headers: Mapping[str, str],
                 body: Optional[bytes] = None, stream: Any = None) -> None:
        self.status_code = status_code
        self.url = url
        self.headers = dict(headers)
        self._body = body
        self._stream = stream

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def content(self) -> bytes:
        if self._body is None:
            self._body = self._stream.read() if self._stream is not None else b""
            self.close()
        return self._body

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Raises ValueError when the body is not JSON (as requests does)."""
        return jsonlib.loads(self.content or b"null")

    def raise_for_status(self) -> None:
        if not self.ok:
            raise HTTPError(f"{self.status_code} for {self.url}", response=self)

    def iter_content(self, chunk_size: int = 65536) -> Iterator[bytes]:
        if self._body is not None:
            yield self._body
            return
        try:
            while True:
                chunk = self._stream.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        except (socket.timeout, TimeoutError) as exc:
            raise Timeout(f"download timed out: {exc}") from None
        except OSError as exc:
            raise ConnectionError(f"download interrupted: {exc}") from None
        finally:
            self.close()

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None          # urllib then hands the 3xx back as an HTTPError, returned as a Response


class Session:
    def __init__(self, follow_redirects: bool = True) -> None:
        self.headers: dict[str, str] = {}
        handlers: list[Any] = [urllib.request.HTTPSHandler(context=ssl.create_default_context())]
        if not follow_redirects:
            handlers.append(_NoRedirect())
        self._opener = urllib.request.build_opener(*handlers)

    def request(
        self,
        method: str,
        url: str,
        timeout: Optional[float] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        params: Optional[Mapping[str, Any]] = None,
        stream: bool = False,
    ) -> Response:
        scheme = urllib.parse.urlparse(url).scheme
        if scheme not in ("http", "https"):
            raise RequestException(f"unsupported URL scheme in {url!r}")
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        headers = dict(self.headers)
        body: Optional[bytes] = None
        if json is not None:
            body = jsonlib.dumps(json).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = data.encode("utf-8") if isinstance(data, str) else data
        req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            raw = self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as err:            # 4xx/5xx (and refused redirects)
            try:
                payload = err.read()
            finally:
                err.close()
            if 300 <= err.code < 400:
                target = (err.headers or {}).get("Location", "?")
                raise HTTPError(f"the server redirected to {target}; redirects are not followed for this "
                                "connection (check the API URL)", response=Response(err.code, url, err.headers or {},
                                                                                    body=payload)) from None
            return Response(err.code, url, err.headers or {}, body=payload)
        except urllib.error.URLError as err:
            if isinstance(err.reason, (socket.timeout, TimeoutError)):
                raise Timeout(f"timed out connecting to {url}") from None
            raise ConnectionError(f"could not connect to {url}: {err.reason}") from None
        except (socket.timeout, TimeoutError):
            raise Timeout(f"timed out waiting for {url}") from None
        except OSError as exc:                            # connection reset and similar
            raise ConnectionError(f"connection to {url} failed: {exc}") from None
        response = Response(raw.status, raw.geturl(), raw.headers, stream=raw)
        if not stream:
            try:
                response.content
            except (socket.timeout, TimeoutError):
                raise Timeout(f"timed out reading the answer from {url}") from None
            except OSError as exc:
                raise ConnectionError(f"connection to {url} failed: {exc}") from None
        return response

    def get(self, url: str, timeout: Optional[float] = None, **kwargs: Any) -> Response:
        return self.request("GET", url, timeout=timeout, **kwargs)

    def post(self, url: str, timeout: Optional[float] = None, **kwargs: Any) -> Response:
        return self.request("POST", url, timeout=timeout, **kwargs)

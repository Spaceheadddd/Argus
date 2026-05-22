from __future__ import annotations

import time
from typing import Dict, Optional

import requests
from requests import Response

from scanner.core.models import Config


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class Requester:
    def __init__(self, config: Config, verbose_print=None):
        self.config = config
        self._verbose = verbose_print  # callable(msg) for verbose logging
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.user_agent or DEFAULT_USER_AGENT,
        })

    def get(
        self,
        url: str,
        params=None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
    ) -> Optional[Response]:
        return self._send("GET", url, params=params, headers=headers,
                          allow_redirects=allow_redirects)

    def post(
        self,
        url: str,
        data=None,
        headers: Optional[Dict] = None,
    ) -> Optional[Response]:
        return self._send("POST", url, data=data, headers=headers)

    def head(self, url: str) -> Optional[Response]:
        return self._send("HEAD", url, allow_redirects=True)

    def _send(self, method: str, url: str, **kwargs) -> Optional[Response]:
        self._before_request(method, url)
        try:
            resp = self.session.request(
                method,
                url,
                timeout=self.config.timeout,
                verify=True,
                **kwargs,
            )
            self._after_request(resp)
            return resp
        except requests.exceptions.SSLError:
            # Retry without SSL verification for self-signed certs
            try:
                resp = self.session.request(
                    method, url, timeout=self.config.timeout,
                    verify=False, **kwargs,
                )
                self._after_request(resp)
                return resp
            except Exception:
                return None
        except Exception as exc:
            if self._verbose:
                self._verbose(f"[dim red]Request error:[/] {exc}")
            return None

    def _before_request(self, method: str, url: str):
        if self.config.delay > 0:
            time.sleep(self.config.delay)
        if self._verbose:
            self._verbose(f"[dim]→ {method} {url}[/]")

    def _after_request(self, resp: Response):
        if self._verbose:
            self._verbose(
                f"[dim]← {resp.status_code} "
                f"({len(resp.content)} bytes)[/]"
            )

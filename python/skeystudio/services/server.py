"""License server helpers for SKey Studio."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from skeystudio.state import OperationResult


@dataclass(frozen=True, slots=True)
class ServerLaunchConfig:
    database_url: str
    server_secret: str
    admin_token: str
    signing_private_key_b64: str
    package_kek_b64: str
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass(frozen=True, slots=True)
class AdminRequest:
    url: str
    headers: dict[str, str]
    payload: dict[str, Any]


class ServerService:
    @staticmethod
    def build_environment(config: ServerLaunchConfig) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "SKEY_SERVER_DATABASE_URL": config.database_url,
                "SKEY_SERVER_SERVER_SECRET": config.server_secret,
                "SKEY_SERVER_ADMIN_TOKEN": config.admin_token,
                "SKEY_SERVER_SIGNING_PRIVATE_KEY_B64": config.signing_private_key_b64,
                "SKEY_SERVER_PACKAGE_KEK_B64": config.package_kek_b64,
                "SKEY_SERVER_ALLOW_DEV_SECRET": "false",
            },
        )
        return env

    @staticmethod
    def start(
        config: ServerLaunchConfig,
        cwd: Path,
    ) -> tuple[OperationResult, subprocess.Popen[str] | None]:
        command = [
            sys.executable,
            "-m",
            "uvicorn",
            "skeyserver.app:create_app",
            "--factory",
            "--host",
            config.host,
            "--port",
            str(config.port),
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=ServerService.build_environment(config),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except OSError as exc:
            return OperationResult.fail(str(exc), code="server_start_failed"), None

        return (
            OperationResult.ok(
                "Server starting",
                detail={"base_url": f"http://{config.host}:{config.port}/v1"},
            ),
            process,
        )

    @staticmethod
    def stop(process: subprocess.Popen[str] | None) -> OperationResult:
        if process is None:
            return OperationResult.ok("Server is already stopped")

        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        return OperationResult.ok("Server stopped")


class AdminApiClient:
    def __init__(self, *, base_url: str, admin_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token

    def product_request(self, *, product_id: str, name: str, version: str) -> AdminRequest:
        return self._request("/admin/products", {"id": product_id, "name": name, "version": version})

    def feature_request(self, *, product_id: str, code: str, name: str) -> AdminRequest:
        return self._request(
            "/admin/features",
            {"product_id": product_id, "code": code, "name": name},
        )

    def package_request(
        self,
        *,
        product_id: str,
        package_id: str,
        package_hash: str,
        version: str,
        package_key_b64: str,
    ) -> AdminRequest:
        return self._request(
            "/admin/packages",
            {
                "product_id": product_id,
                "package_id": package_id,
                "package_hash": package_hash,
                "version": version,
                "package_key_b64": package_key_b64,
            },
        )

    def license_request(
        self,
        *,
        license_id: str,
        product_id: str,
        license_code: str,
        customer_id: str | None,
        max_activations: int,
        expire_at: datetime,
    ) -> AdminRequest:
        return self._request(
            "/admin/licenses",
            {
                "license_id": license_id,
                "product_id": product_id,
                "license_code": license_code,
                "customer_id": customer_id,
                "max_activations": max_activations,
                "expire_at": expire_at.isoformat(),
                "status": "active",
            },
        )

    def license_feature_request(
        self,
        *,
        license_id: str,
        product_id: str,
        feature_code: str,
        enabled: bool,
    ) -> AdminRequest:
        escaped_license_id = urllib.parse.quote(license_id, safe="")
        return self._request(
            f"/admin/licenses/{escaped_license_id}/features",
            {"product_id": product_id, "feature_code": feature_code, "enabled": enabled},
        )

    def send(self, request: AdminRequest) -> OperationResult:
        http_request = urllib.request.Request(
            request.url,
            data=json.dumps(request.payload, sort_keys=True).encode("utf-8"),
            headers=request.headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=10) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            return OperationResult.fail(str(exc), code="admin_api_failed")

        return OperationResult.ok("Admin request completed", detail={"response": response_payload})

    def _request(self, path: str, payload: dict[str, Any]) -> AdminRequest:
        return AdminRequest(
            url=f"{self.base_url}{path}",
            headers={"Content-Type": "application/json", "X-Admin-Token": self.admin_token},
            payload=payload,
        )

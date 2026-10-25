"""비번 금고 (데모용). 비밀번호는 Fernet으로 암호화해 vault.json에 저장한다.

키는 .env의 VAULT_KEY. 없으면 새로 만들어 .env에 추가한다.
이 모듈의 어떤 함수도 비밀번호 원문을 로그로 남기지 않는다. 원문을 돌려주는 건 get_password() 하나뿐이며,
MCP 도구에서는 절대 호출하지 말 것 (내 PC 전용 show_password.py, 자동 변경 내부 처리에서만 사용).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
VAULT_FILE = Path(os.getenv("VAULT_FILE") or ROOT / "vault.json")

load_dotenv(ENV_FILE)


def _norm(name: str) -> str:
    return "".join((name or "").lower().split())


def ensure_key() -> str:
    key = os.getenv("VAULT_KEY", "").strip()
    if key:
        return key
    key = Fernet.generate_key().decode("ascii")
    prefix = ""
    if ENV_FILE.exists() and not ENV_FILE.read_text(encoding="utf-8").endswith("\n"):
        prefix = "\n"
    with ENV_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{prefix}# 비번 금고 암호화 키 (잃어버리면 vault.json을 못 엽니다. 절대 공유 금지)\nVAULT_KEY={key}\n")
    os.environ["VAULT_KEY"] = key
    return key


def _fernet() -> Fernet:
    return Fernet(ensure_key().encode("ascii"))


def _load() -> dict[str, Any]:
    if not VAULT_FILE.exists():
        return {"entries": {}}
    return json.loads(VAULT_FILE.read_text(encoding="utf-8"))


def _save(data: dict[str, Any]) -> None:
    tmp = VAULT_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    replace_with_retry(tmp, VAULT_FILE)


def replace_with_retry(src: Path, dst: Path, attempts: int = 20) -> None:
    """Windows에서 백신/인덱서가 방금 쓴 파일을 잠깐 잡고 있으면 replace가 실패하므로 재시도."""
    for i in range(attempts):
        try:
            src.replace(dst)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(0.1)


def put(service: str, password: str, username: str = "", url: str = "", source: str = "") -> None:
    data = _load()
    data["entries"][_norm(service)] = {
        "service": service,
        "username": username,
        "url": url,
        "secret": _fernet().encrypt(password.encode("utf-8")).decode("ascii"),
        "source": source,
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _save(data)


def has(service: str) -> bool:
    return _norm(service) in _load()["entries"]


def entry(service: str) -> dict[str, Any] | None:
    """비밀번호를 뺀 메타데이터만."""
    e = _load()["entries"].get(_norm(service))
    if not e:
        return None
    return {k: v for k, v in e.items() if k != "secret"}


def services() -> list[str]:
    return [e["service"] for e in _load()["entries"].values()]


def get_password(service: str) -> str | None:
    """비밀번호 원문. MCP 도구 응답/로그/알림에 절대 넣지 말 것."""
    e = _load()["entries"].get(_norm(service))
    if not e:
        return None
    return _fernet().decrypt(e["secret"].encode("ascii")).decode("utf-8")


def fingerprint(password: str) -> str:
    """같은 비번인지 비교용 지문 (키로 HMAC, 저장하지 않음)."""
    return hmac.new(ensure_key().encode("ascii"), password.encode("utf-8"), hashlib.sha256).hexdigest()


def fingerprints() -> dict[str, str]:
    """서비스명 → 지문. 메모리에서만 쓰고 버린다."""
    f = _fernet()
    out = {}
    for e in _load()["entries"].values():
        out[e["service"]] = fingerprint(f.decrypt(e["secret"].encode("ascii")).decode("utf-8"))
    return out


def reset() -> None:
    _save({"entries": {}})

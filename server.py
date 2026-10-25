"""먼저지킴 MCP 서버 (FastMCP, Streamable HTTP).

개인정보 유출 사고를 먼저 감시하고, 내가 쓰는 서비스가 해당되면 ntfy 푸시로 먼저 알리고,
대응 할 일을 준비·추적한다. 비밀번호 원본은 절대 받거나 저장하지 않고 "A그룹" 같은 꼬리표로만 관리한다.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import fnmatch
import hashlib
import secrets
import string
import html
import json
import logging
import os
import re
import uuid
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

import vault

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("meonjeojikim")

# ---------------------------------------------------------------------------
# 설정
# ---------------------------------------------------------------------------

NTFY_TOPIC = os.getenv("NTFY_TOPIC", "").strip()
NTFY_SERVER = (os.getenv("NTFY_SERVER", "").strip() or "https://ntfy.sh").rstrip("/")
NTFY_TITLE = "먼저지킴"
USER_NAME = os.getenv("USER_NAME", "").strip() or "사용자"
DATA_FILE = Path(os.getenv("DATA_FILE") or Path(__file__).with_name("data.json"))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


WATCH_INTERVAL_MIN = _int_env("WATCH_INTERVAL_MIN", 60)
REMIND_INTERVAL_MIN = _int_env("REMIND_INTERVAL_MIN", 60)

ROOT = Path(__file__).resolve().parent
# 알림의 데모몰 바로가기 주소 (ngrok 등으로 공개했다면 그 주소로)
PUBLIC_BASE_URL = (os.getenv("PUBLIC_BASE_URL", "").strip() or f"http://127.0.0.1:{PORT}").rstrip("/")
# 자동 변경 때 서버가 스스로 부르는 데모몰 API
DEMO_MALL_API = f"http://127.0.0.1:{PORT}/demo-mall"
DEMO_MALL_NAME = "데모몰"
DEMO_MALL_FILE = Path(os.getenv("DEMO_MALL_FILE") or ROOT / "demo_mall.json")
SAMPLE_CSV = ROOT / "sample_passwords.csv"
DOWNLOADS_DIR = Path(os.getenv("DOWNLOADS_DIR") or Path.home() / "Downloads")
WATCH_DOWNLOADS = os.getenv("WATCH_DOWNLOADS", "1").strip() != "0"
DOWNLOADS_PATTERN = "*assword*.csv"
KST = timezone(timedelta(hours=9))

# 심각도: (이모지, 라벨, ntfy Priority)
SEVERITY = {
    "urgent": ("🔴", "긴급", "urgent"),
    "high": ("🟠", "위험", "high"),
    "normal": ("🟡", "주의", "default"),
}
SENSITIVE_ITEMS = ["비밀번호", "주민등록번호", "유심"]
# 자동 비번 변경을 지원하는 서비스 (지금은 데모몰만)
AUTO_CHANGE_SUPPORTED = {DEMO_MALL_NAME}

HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_USER_AGENT = "meonjeojikim-mcp/1.0 (personal breach watcher)"
GOOGLE_NEWS_RSS_URL = "https://news.google.com/rss/search"
NEWS_USER_AGENT = "Mozilla/5.0 (compatible; meonjeojikim-mcp/1.0)"

LINK_PORTAL = "https://www.privacy.go.kr"
LINK_KIDC = "https://kidc.eprivacy.go.kr"
LINK_MSAFER = "https://www.msafer.or.kr"

Category = Literal["통신사", "쇼핑", "배달", "카드", "기타"]

# 종류별로 보통 맡기는 정보
CATEGORY_STORED_INFO: dict[str, list[str]] = {
    "통신사": ["이름", "전화번호", "주소", "생년월일", "주민등록번호", "유심", "결제정보"],
    "쇼핑": ["이름", "전화번호", "주소", "이메일", "카드"],
    "배달": ["이름", "전화번호", "주소", "카드"],
    "카드": ["이름", "전화번호", "주소", "카드", "주민등록번호", "이메일"],
    "기타": ["이름", "이메일", "전화번호"],
}

# 이름만 보고 종류를 추정할 때 쓰는 단서
CATEGORY_HINTS: dict[str, list[str]] = {
    "통신사": ["skt", "sk텔레콤", "kt", "lg유플러스", "lgu+", "유플러스", "알뜰폰", "텔레콤", "모바일", "헬로", "u+"],
    "배달": ["배달의민족", "배민", "요기요", "쿠팡이츠", "땡겨요", "배달"],
    "카드": ["카드", "card", "페이", "pay"],
    "쇼핑": ["쿠팡", "11번가", "g마켓", "지마켓", "옥션", "위메프", "티몬", "ssg", "롯데온", "무신사",
             "에이블리", "지그재그", "29cm", "마켓컬리", "컬리", "오늘의집", "알리", "테무", "쇼핑", "몰", "마켓"],
}

# HIBP(영문)와 매칭하기 위한 한국 서비스 별칭
SERVICE_ALIASES: dict[str, list[str]] = {
    "쿠팡": ["coupang", "coupang.com"],
    "네이버": ["naver", "naver.com"],
    "카카오": ["kakao", "kakao.com"],
    "11번가": ["11st", "11st.co.kr"],
    "인터파크": ["interpark", "interpark.com"],
    "야놀자": ["yanolja", "yanolja.com"],
    "여기어때": ["goodchoice", "yeogi", "goodchoice.kr"],
    "배달의민족": ["baemin", "baemin.com"],
    "요기요": ["yogiyo", "yogiyo.co.kr"],
    "무신사": ["musinsa", "musinsa.com"],
    "지마켓": ["gmarket", "gmarket.co.kr"],
    "g마켓": ["gmarket", "gmarket.co.kr"],
    "옥션": ["auction", "auction.co.kr"],
    "티몬": ["tmon", "tmon.co.kr"],
    "위메프": ["wemakeprice", "wemakeprice.com"],
    "skt": ["sk telecom", "sktelecom", "sktelecom.com"],
    "sk텔레콤": ["sk telecom", "sktelecom", "sktelecom.com"],
    "kt": ["kt corporation", "kt.com"],
    "lg유플러스": ["lg uplus", "lguplus", "uplus.co.kr"],
}

# 유출 판단 키워드 / 유출 항목 키워드
BREACH_KEYWORDS = ["유출", "해킹", "침해"]
LEAK_ITEM_KEYWORDS: dict[str, list[str]] = {
    "전화번호": ["전화번호", "휴대폰번호", "휴대전화번호", "휴대폰 번호", "연락처"],
    "주소": ["주소", "배송지"],
    "이메일": ["이메일", "메일 주소", "e메일"],
    "카드": ["카드번호", "카드 번호", "카드정보", "카드 정보", "결제정보", "결제 정보"],
    "주민등록번호": ["주민등록번호", "주민번호"],
    "유심": ["유심", "usim", "가입자식별", "imsi"],
    "비밀번호": ["비밀번호", "패스워드", "password"],
    "이름": ["이름", "성명"],
    "생년월일": ["생년월일"],
    "계좌": ["계좌번호", "계좌 정보"],
}
HIBP_CLASS_MAP: dict[str, str] = {
    "Phone numbers": "전화번호",
    "Physical addresses": "주소",
    "Email addresses": "이메일",
    "Credit cards": "카드",
    "Partial credit card data": "카드",
    "Credit card CVV": "카드",
    "Government issued IDs": "주민등록번호",
    "National identification numbers": "주민등록번호",
    "Passwords": "비밀번호",
    "Names": "이름",
    "Dates of birth": "생년월일",
    "Bank account numbers": "계좌",
}

PORTAL_TIP = f"안 쓰는 사이트는 개인정보 포털에서 탈퇴하면 털릴 곳이 줄어요 ({LINK_PORTAL})"

# ---------------------------------------------------------------------------
# 저장소 (data.json)
# ---------------------------------------------------------------------------

_store_lock = asyncio.Lock()
_check_lock = asyncio.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _now()).isoformat(timespec="seconds")


def _empty_store() -> dict[str, Any]:
    return {"services": [], "incidents": [], "actions": [], "seen": {"links": [], "hibp": []}}


def _load() -> dict[str, Any]:
    if not DATA_FILE.exists():
        data = _empty_store()
        _save(data)
        return data
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.error("data.json 읽기 실패, 백업 후 새로 만듭니다: %s", e)
        try:
            DATA_FILE.replace(DATA_FILE.with_suffix(f".broken-{int(_now().timestamp())}.json"))
        except OSError:
            pass
        data = _empty_store()
        _save(data)
        return data
    for key, val in _empty_store().items():
        data.setdefault(key, val)
    data["seen"].setdefault("links", [])
    data["seen"].setdefault("hibp", [])
    return data


def _save(data: dict[str, Any]) -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = DATA_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    vault.replace_with_retry(tmp, DATA_FILE)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 유틸
# ---------------------------------------------------------------------------


def _norm(s: str) -> str:
    return re.sub(r"[\s\-_.()㈜]+", "", (s or "").lower())


def _guess_category(name: str) -> str:
    n = _norm(name)
    for cat in ("배달", "통신사", "카드", "쇼핑"):  # 배달을 쇼핑보다 먼저 (쿠팡이츠)
        for hint in CATEGORY_HINTS[cat]:
            h = _norm(hint)
            if cat == "통신사" and len(h) <= 3:
                if n == h:  # "kt" 같은 짧은 단서는 정확히 일치할 때만
                    return cat
            elif h in n:
                return cat
    return "기타"


def _looks_like_password(label: str) -> bool:
    """꼬리표 자리에 실제 비밀번호를 넣은 것 같으면 True."""
    if not label:
        return False
    if len(label) > 20:
        return True
    has_digit = any(c.isdigit() for c in label)
    has_alpha = any(c.isalpha() for c in label)
    has_special = any(not c.isalnum() and not c.isspace() for c in label)
    return len(label) >= 8 and has_digit and has_alpha and has_special


def _strip_html(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


_NEGATION_RE = re.compile(r"(안\s?[돼되됐]|않|제외|없|무관|아니)")


def _negated_after(t: str, end: int) -> bool:
    """키워드 바로 뒤(같은 구절 안)가 부정 표현이면 True. 예: '유출 안 돼', '해킹은 아니라지만'."""
    tail = re.split(r"[.,·…]", t[end:end + 15])[0]
    return bool(_NEGATION_RE.search(tail))


def _has_breach_signal(text: str) -> bool:
    """유출·해킹·침해 키워드가 부정되지 않은 채로 하나라도 있으면 True."""
    t = (text or "").lower()
    return any(not _negated_after(t, m.end())
               for k in BREACH_KEYWORDS for m in re.finditer(re.escape(k), t))


def _extract_leak_items(text: str) -> list[str]:
    """키워드로 유출 항목 추출. '카드번호는 유출 안 돼'처럼 바로 뒤가 부정이면 제외."""
    t = (text or "").lower()
    found = []
    for item, kws in LEAK_ITEM_KEYWORDS.items():
        for k in kws:
            for m in re.finditer(re.escape(k.lower()), t):
                if not _negated_after(t, m.end()):
                    found.append(item)
                    break
            if item in found:
                break
    return found


def _service_keys(svc: dict[str, Any]) -> set[str]:
    keys = {_norm(svc["name"])}
    keys.update(_norm(a) for a in SERVICE_ALIASES.get(svc["name"].lower(), []))
    keys.update(_norm(a) for a in SERVICE_ALIASES.get(svc["name"], []))
    if svc.get("domain"):
        keys.add(_norm(re.sub(r"^(https?://)?(www\.)?", "", svc["domain"].lower())))
    return {k for k in keys if k}


def _j(word: str, pair: str) -> str:
    """조사 붙이기: _j("쿠팡", "은/는") -> "쿠팡은"."""
    with_b, without_b = pair.split("/")
    last = (word or " ")[-1]
    if "가" <= last <= "힣":
        has_b = (ord(last) - 0xAC00) % 28 != 0
    else:
        has_b = last.lower() in "lmn0136789"
    return word + (with_b if has_b else without_b)


def _reuse_warnings(data: dict[str, Any]) -> list[str]:
    groups: dict[str, list[str]] = {}
    for s in data["services"]:
        if s.get("password_group"):
            groups.setdefault(s["password_group"], []).append(s["name"])
    return [f"같은 비번을 {len(m)}곳에서 쓰고 있어요 ({g}: {', '.join(m)})"
            for g, m in groups.items() if len(m) >= 2]


def _group_members(data: dict[str, Any], group: str | None, exclude: str | None = None) -> list[str]:
    if not group:
        return []
    return [s["name"] for s in data["services"]
            if s.get("password_group") == group and s["name"] != exclude]


# ---------------------------------------------------------------------------
# bulk_text 파싱 (e프라이버시 클린서비스 복사 텍스트)
# ---------------------------------------------------------------------------

_HEADER_WORDS = {"번호", "no", "사이트명", "사이트", "웹사이트명", "홈페이지", "가입일", "가입일자", "최근이용일",
                 "본인확인일", "본인확인일자", "확인일", "확인기관", "본인확인기관", "도메인", "url", "탈퇴",
                 "탈퇴요청", "회원탈퇴", "선택", "전체", "조회", "결과", "본인확인내역", "이용내역"}
_DATE_RE = re.compile(r"\d{4}[.\-/년]\s?\d{1,2}[.\-/월]\s?\d{1,2}일?(\s?\d{1,2}:\d{2}(:\d{2})?)?")
_URL_RE = re.compile(r"(https?://)?((?:[a-z0-9\-]+\.)+(?:com|net|kr|co\.kr|or\.kr|go\.kr|io|me|org|shop|store))\S*", re.I)
_SKIP_LINE_RE = re.compile(r"(아이핀|휴대폰|신용카드|공동인증|범용인증|나이스|코리아크레딧|서울신용|드림시큐리티|sci평가)", re.I)


def _parse_bulk_text(text: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        domain = None
        m = _URL_RE.search(line)
        if m:
            domain = re.sub(r"^www\.", "", m.group(2).lower())
            line = _URL_RE.sub(" ", line)
        line = _DATE_RE.sub(" ", line)
        fields = [f.strip() for f in re.split(r"\t|\s{2,}|\||,", line) if f.strip()]
        name = None
        for f in fields:
            f = re.sub(r"^\d+(?:[.)]\s*|\s+)", "", f).strip()  # 앞 번호 제거 ("11번가"는 유지)
            f = re.sub(r"[\s(\[{<]+$", "", f).strip()  # URL 빼고 남은 여는 괄호 제거
            if not f or f.isdigit() or _norm(f) in _HEADER_WORDS:
                continue
            if _SKIP_LINE_RE.search(f) and len(fields) > 1:  # 본인확인 수단 칸은 건너뜀
                continue
            if len(f) > 40:
                continue
            name = f
            break
        if not name and domain:
            name = domain
        if not name:
            continue
        key = _norm(name)
        if key in seen:
            continue
        seen.add(key)
        item = {"name": name}
        if domain:
            item["domain"] = domain
        results.append(item)
    return results


# ---------------------------------------------------------------------------
# 외부 API (모든 실패는 삼키고 에러 메시지로 돌려준다)
# ---------------------------------------------------------------------------

_hibp_cache: dict[str, Any] = {"at": None, "data": None}


async def _fetch_hibp(client: httpx.AsyncClient) -> tuple[list[dict[str, Any]], str | None]:
    cached_at = _hibp_cache["at"]
    if cached_at and _now() - cached_at < timedelta(minutes=30) and _hibp_cache["data"] is not None:
        return _hibp_cache["data"], None
    try:
        r = await client.get(HIBP_URL, headers={"User-Agent": HIBP_USER_AGENT}, timeout=20)
        r.raise_for_status()
        data = r.json()
        _hibp_cache.update(at=_now(), data=data)
        return data, None
    except Exception as e:  # noqa: BLE001
        log.warning("HIBP 조회 실패: %s", e)
        return [], f"HIBP 조회 실패: {e}"


async def _search_google_news(client: httpx.AsyncClient, query: str) -> tuple[list[dict[str, Any]], str | None]:
    """구글 뉴스 RSS 검색. 키 불필요. 각 기사를 {title, description, link, pubDate}로 돌려준다."""
    try:
        r = await client.get(
            GOOGLE_NEWS_RSS_URL,
            params={"q": query, "hl": "ko", "gl": "KR", "ceid": "KR:ko"},
            headers={"User-Agent": NEWS_USER_AGENT},
            timeout=20,
        )
        r.raise_for_status()
        root = ET.fromstring(r.content)
        items = []
        for it in root.iterfind("./channel/item"):
            title = it.findtext("title") or ""
            source = it.findtext("source") or ""
            if source and title.endswith(f" - {source}"):  # "제목 - 언론사" 꼬리 제거
                title = title[: -len(f" - {source}")]
            items.append({
                "title": title,
                "description": it.findtext("description") or "",
                "link": it.findtext("link") or "",
                "pubDate": it.findtext("pubDate") or "",
                "press": source,
            })
        return items, None
    except Exception as e:  # noqa: BLE001
        log.warning("구글 뉴스 검색 실패(%s): %s", query, e)
        return [], f"구글 뉴스 검색 실패({query}): {e}"


def _rfc2047(value: str) -> str:
    """HTTP 헤더에 한글을 안전하게 싣기 위한 인코딩 (ntfy가 지원)."""
    return f"=?UTF-8?B?{base64.b64encode(value.encode('utf-8')).decode('ascii')}?="


async def _send_alert(text: str, priority: str = "high", click: str | None = None,
                      tags: str = "rotating_light") -> str:
    """ntfy로 푸시 알림 전송. 본문은 UTF-8 그대로, 한글 제목은 RFC 2047로 인코딩.
    공개 채널이므로 비밀번호 원문은 절대 넣지 않는다."""
    if not NTFY_TOPIC:
        return "skipped (NTFY_TOPIC 미설정)"
    headers = {
        "Title": _rfc2047(NTFY_TITLE),
        "Priority": priority,
        "Tags": tags,
        "Content-Type": "text/plain; charset=utf-8",
    }
    if click:
        headers["Click"] = click
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{NTFY_SERVER}/{NTFY_TOPIC}",
                content=text.encode("utf-8"),
                headers=headers,
                timeout=15,
            )
            r.raise_for_status()
        return "sent"
    except Exception as e:  # noqa: BLE001
        log.warning("ntfy 알림 전송 실패: %s", e)
        return f"failed: {e}"


# ---------------------------------------------------------------------------
# 대응 계획 생성
# ---------------------------------------------------------------------------


BASIS_DEFAULT = "기본"       # 유출 항목과 상관없이 늘 하는 일
BASIS_CONFIRMED = "확인됨"   # 기사/HIBP에서 유출이 확인된 항목에 대한 조치
BASIS_PREVENTIVE = "예방"    # 확인되진 않았지만 그 서비스에 맡긴 정보라 미리 대비

# stored_info 표기를 유출 항목 표기로 맞춤
_STORED_TO_ITEM = {"결제정보": "카드"}


def _item_basis(incident: dict[str, Any], svc: dict[str, Any] | None) -> tuple[list[str], list[str]]:
    """(확인된 항목, 예방 차원 항목). 뉴스 사고는 확인 항목 + 맡긴 정보를 합치고,
    HIBP 사고는 유출 항목이 정확하므로 확인 항목이 없을 때만 맡긴 정보로 대비한다."""
    confirmed = list(incident.get("leaked_items") or [])
    stored = []
    for s in (svc or {}).get("stored_info", []):
        item = _STORED_TO_ITEM.get(s, s)
        if item not in stored:
            stored.append(item)
    if incident.get("source") == "hibp" and confirmed:
        return confirmed, []
    return confirmed, [s for s in stored if s not in confirmed]


def _plan_steps(data: dict[str, Any], incident: dict[str, Any]) -> list[dict[str, Any]]:
    svc = next((s for s in data["services"] if s["name"] == incident["service"]), None)
    name = incident["service"]
    group = (svc or {}).get("password_group")
    steps: list[dict[str, Any]] = [
        {"title": f"{name} 비밀번호 변경",
         "detail": f"{name}에 로그인해 비밀번호를 새로 바꾸세요. 다른 곳에서 안 쓰는 새 비밀번호로요."
                   + (f" (현재 꼬리표: {group})" if group else ""),
         "link": "", "basis": BASIS_DEFAULT, "items": []},
    ]
    for other in _group_members(data, group, exclude=name):
        steps.append({"title": f"{other} 비밀번호도 변경 (같은 {group})",
                      "detail": f"{_j(other, '은/는')} {_j(name, '과/와')} 같은 비밀번호 꼬리표({group})예요. 같은 비번이면 연쇄로 뚫릴 수 있어 같이 바꾸세요.",
                      "link": "", "basis": BASIS_DEFAULT, "items": []})
    steps.append({"title": "털린 내 정보 찾기에서 계정 유출 여부 조회",
                  "detail": "내 아이디/비밀번호가 유출 DB에 있는지 정부 서비스에서 확인하세요.",
                  "link": LINK_KIDC, "basis": BASIS_DEFAULT, "items": []})

    confirmed, preventive = _item_basis(incident, svc)

    def item_step(triggers: list[str], title: str, detail: str, link: str = "",
                  prev_title: str | None = None, prev_detail: str | None = None) -> None:
        """triggers 중 확인된 항목이 있으면 확인 조치, 맡긴 정보에만 있으면 (더 가벼운) 예방 조치."""
        hit = [t for t in triggers if t in confirmed]
        if hit:
            steps.append({"title": title, "link": link, "basis": BASIS_CONFIRMED, "items": hit,
                          "detail": f"[유출 확인: {', '.join(hit)}] {detail}"})
            return
        hit = [t for t in triggers if t in preventive]
        if hit:
            steps.append({"title": prev_title or title, "link": link, "basis": BASIS_PREVENTIVE, "items": hit,
                          "detail": f"[예방 차원: {name}에 맡긴 {', '.join(hit)}] {prev_detail or detail}"})

    item_step(["전화번호", "주민등록번호"], "명의도용방지서비스 가입",
              "내 명의로 휴대폰이 몰래 개통되는 걸 막아줘요 (엠세이퍼, 무료).", LINK_MSAFER)
    item_step(["카드"], "카드사 분실신고·재발급",
              f"{name}에 등록한 카드사 고객센터(앱)에서 분실신고 후 재발급 받으세요. 해외결제 차단도 같이요.",
              prev_title="카드 결제 알림 켜고 이상 결제 확인",
              prev_detail="카드번호 유출은 확인되지 않았어요. 카드사 앱에서 결제 알림을 켜고 최근 결제 내역에 모르는 결제가 없는지 보세요. "
                          "이상하면 그때 분실신고하면 돼요.")
    item_step(["유심"], "통신사 유심보호서비스 가입",
              "통신사 앱/고객센터에서 유심보호서비스(무료)를 켜서 유심 복제를 막으세요. 필요하면 유심 교체도요.")
    item_step(["주소"], "택배 사칭 문자 주의",
              "주소가 털리면 '배송지 확인' 같은 택배 사칭 스미싱이 늘어요. 문자 속 링크는 누르지 마세요.")
    item_step(["이메일"], "피싱 메일 주의",
              f"{_j(name, '을/를')} 사칭한 '보상 안내' 메일이 올 수 있어요. 메일 링크 대신 공식 앱으로 확인하세요.")

    steps.append({"title": "가족에게 주의 문자 보내기",
                  "detail": "get_action_plan의 가족 문자 초안을 보내 가족도 사칭 연락에 대비하게 하세요.",
                  "link": "", "basis": BASIS_DEFAULT, "items": []})
    return steps


def _family_draft(incident: dict[str, Any], confirmed: list[str]) -> str:
    name = incident["service"]
    item_txt = f" (확인된 유출: {', '.join(confirmed)})" if confirmed else ""
    return (f"[주의] {name}에서 개인정보 유출 사고가 있었대요{item_txt}. "
            f"앞으로 {name}·택배·카드사·검찰 등을 사칭한 문자나 전화가 올 수 있어요. "
            "문자 속 링크는 누르지 말고, 돈이나 인증번호를 요구하면 바로 끊고 나한테 먼저 연락 줘요.")


def _compensation_draft(incident: dict[str, Any], items: list[str]) -> str:
    name = incident["service"]
    item_txt = ", ".join(items) if items else "개인정보"
    return (f"{name} 고객센터 담당자님께\n\n"
            f"저는 {name} 회원 {USER_NAME}입니다. 최근 보도된 {name} 개인정보 유출 사고와 관련하여 문의드립니다.\n"
            f"1. 제 계정의 유출 여부와 유출된 항목({item_txt} 등)을 구체적으로 알려주시기 바랍니다.\n"
            "2. 유출 이후 저에게 발생한 피해(무단 결제, 사칭 연락 등)에 대해 아래와 같이 보상을 요청합니다.\n"
            "   - 피해 내용: [발생 일시 / 피해 내용 / 금액을 적어주세요]\n"
            "3. 재발 방지 대책과 추가 피해 예방 조치(모니터링, 카드 재발급 비용 부담 등)를 안내해주시기 바랍니다.\n\n"
            "회신은 [연락처 또는 이메일]로 부탁드립니다. 답변이 없거나 미흡한 경우 개인정보 분쟁조정위원회(개인정보 포털) "
            "조정 신청을 검토하겠습니다.\n\n"
            f"{USER_NAME} 드림")


def _sync_actions(data: dict[str, Any], incident: dict[str, Any]) -> list[dict[str, Any]]:
    """사고의 할 일을 현재 계획에 맞춘다. 새 사고면 전부 만들고, 기존 사고에 유출 항목이 새로 확인되면
    예방 조치를 확인 조치로 올리거나(같은 제목) 대체한다(카드처럼 제목이 다른 경우). 새로 생긴 할 일을 돌려준다."""
    steps = _plan_steps(data, incident)
    step_titles = {s["title"] for s in steps}
    existing = {a["title"]: a for a in data["actions"] if a["incident_id"] == incident["id"]}
    # 확인 조치로 대체된, 아직 안 한 예방 조치는 정리
    data["actions"] = [a for a in data["actions"]
                       if not (a["incident_id"] == incident["id"] and not a["done"]
                               and a.get("basis") == BASIS_PREVENTIVE and a["title"] not in step_titles)]
    created = []
    for step in steps:
        action = existing.get(step["title"])
        if action:
            action.update(basis=step["basis"], items=step["items"])  # 완료한 일도 근거 라벨은 갱신
            if not action["done"]:
                action["detail"] = step["detail"]
            continue
        action = {
            "id": _new_id("act"),
            "incident_id": incident["id"],
            "service": incident["service"],
            "title": step["title"],
            "detail": step["detail"],
            "link": step["link"],
            "basis": step["basis"],
            "items": step["items"],
            "done": False,
            "created_at": _iso(),
            "completed_at": None,
        }
        data["actions"].append(action)
        created.append(action)
    incident["action_ids"] = [a["id"] for a in data["actions"] if a["incident_id"] == incident["id"]]
    return created


def _severity(incident: dict[str, Any]) -> tuple[str, list[str]]:
    """(urgent|high|normal, 판단 이유)."""
    source = incident.get("source")
    sensitive = [i for i in SENSITIVE_ITEMS if i in (incident.get("leaked_items") or [])]
    if source == "simulation":
        return "urgent", ["데모 시뮬레이션"] + ([f"민감 항목: {', '.join(sensitive)}"] if sensitive else [])
    reasons: list[str] = []
    n_articles = n_press = 0
    if source == "google_news":
        n_articles = len(incident.get("links") or [])
        n_press = len(set(incident.get("press") or []))
        reasons += [f"기사 {n_articles}건", f"언론사 {n_press}곳"]
    else:
        reasons.append("Have I Been Pwned 등록 사고")
    if sensitive:
        reasons.append(f"민감 항목: {', '.join(sensitive)}")
    if n_articles >= 10 or sensitive:
        return "urgent", reasons
    if n_articles >= 5 or n_press >= 3:
        return "high", reasons
    return "normal", reasons


def _apply_severity(incident: dict[str, Any]) -> None:
    incident["severity"], incident["severity_reasons"] = _severity(incident)


def _severity_label(level: str) -> str:
    emoji, label, _ = SEVERITY.get(level, SEVERITY["normal"])
    return f"{emoji}{label}"


def _change_password_url(svc: dict[str, Any] | None) -> str | None:
    """비번 변경 바로가기 (ntfy Click). 표준 /.well-known/change-password 사용."""
    if not svc:
        return None
    if svc["name"] == DEMO_MALL_NAME:
        return f"{PUBLIC_BASE_URL}/demo-mall/change-password"
    domain = svc.get("domain")
    if not domain:
        return None
    host = re.sub(r"^(https?://)?(www\.)?", "", domain.lower()).split("/")[0]
    return f"https://{host}/.well-known/change-password"


def _kst_hhmm() -> str:
    return datetime.now(KST).strftime("%H:%M")


def _alert_text(incident: dict[str, Any], n_actions: int, preventive: list[str],
                auto: dict[str, Any] | None = None) -> str:
    """알림 본문. 비밀번호 원문은 절대 넣지 않는다."""
    name = incident["service"]
    sev = _severity_label(incident.get("severity", "normal"))
    items = incident.get("leaked_items") or []
    if auto and auto.get("changed"):
        changed, manual = auto["changed"], auto["manual"]
        if name in changed:
            head = f"{sev} {name} 유출 감지 → 비번 자동 변경 완료 ({auto['at']}). 새 비번은 금고에서 확인하세요."
            if manual:
                head += f" 같은 비번을 쓰던 {_j('·'.join(manual), '은/는')} 직접 바꿔주세요"
        else:
            head = (f"{sev} {name} 유출 감지 → 같은 비번을 쓰던 {'·'.join(changed)} 비번 자동 변경 완료 ({auto['at']}). "
                    f"새 비번은 금고에서 확인하세요. {_j('·'.join(manual), '은/는')} 직접 바꿔주세요")
        if auto.get("failed"):
            head += f"\n⚠️ {'·'.join(auto['failed'])} 자동 변경 실패, 직접 바꿔주세요"
    elif auto and auto.get("failed"):
        head = f"{sev} {name} 유출 감지 → {'·'.join(auto['failed'])} 자동 변경 실패, 직접 바꿔주세요. (기존 비번 유지)"
        others = [m for m in auto.get("manual", []) if m not in auto["failed"]]
        if others:
            head += f" 같은 비번을 쓰던 {'·'.join(others)}도 직접 바꿔주세요"
    else:
        head = f"{sev} {name} 개인정보 유출 소식이 있어요. {USER_NAME}님 해당돼요. 대응 준비 다 해뒀어요. (할 일 {n_actions}개)"
    lines = [head]
    if incident.get("severity_reasons"):
        lines.append(f"판단 근거: {', '.join(incident['severity_reasons'])}")
    lines.append(f"확인된 유출 항목: {', '.join(items) if items else '아직 확인 안 됨'}")
    if preventive:
        lines.append(f"예방 차원 대비: {', '.join(preventive)} (맡긴 정보)")
    if incident.get("title"):
        lines.append(f"내용: {incident['title']}")
    if incident.get("links"):
        lines.append(f"출처: {incident['links'][0]}")
    if auto and auto.get("changed"):
        lines.append(f"남은 할 일 {n_actions}개")
    lines.append(f"먼저 할 일: 털린 내 정보 찾기 조회 {LINK_KIDC}")
    lines.append(f"사고 ID: {incident['id']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 데모몰 (테스트용 가짜 쇼핑몰) - 비번은 해시로만 저장
# ---------------------------------------------------------------------------


def _hash_pw(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def _sample_demo_account() -> tuple[str, str]:
    """sample_passwords.csv의 데모몰 계정 (초기 비번을 같게 맞춘다)."""
    try:
        with SAMPLE_CSV.open(encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                host = urlparse(row.get("url") or "").hostname or ""
                if host in ("localhost", "127.0.0.1") or (row.get("name") or "").strip() == DEMO_MALL_NAME:
                    return row["username"], row["password"]
    except OSError:
        pass
    return "sua@demo.test", secrets.token_urlsafe(12)


def _demo_load() -> dict[str, Any]:
    if DEMO_MALL_FILE.exists():
        return json.loads(DEMO_MALL_FILE.read_text(encoding="utf-8"))
    username, password = _sample_demo_account()
    salt, digest = _hash_pw(password)
    acct = {"username": username, "salt": salt, "hash": digest,
            "changed_at": _iso(), "changed_by": "초기 설정 (sample_passwords.csv)"}
    DEMO_MALL_FILE.write_text(json.dumps(acct, ensure_ascii=False, indent=2), encoding="utf-8")
    return acct


def _demo_verify(username: str, password: str) -> bool:
    acct = _demo_load()
    if (username or "").strip().lower() != acct["username"].lower():
        return False
    _, digest = _hash_pw(password or "", bytes.fromhex(acct["salt"]))
    return secrets.compare_digest(digest.encode(), acct["hash"].encode())


def _demo_set_password(new_password: str, by: str) -> str:
    acct = _demo_load()
    acct["salt"], acct["hash"] = _hash_pw(new_password)
    acct["changed_at"] = _iso()
    acct["changed_by"] = by
    DEMO_MALL_FILE.write_text(json.dumps(acct, ensure_ascii=False, indent=2), encoding="utf-8")
    return acct["changed_at"]


# ---------------------------------------------------------------------------
# 자동 비번 변경 (데모)
# ---------------------------------------------------------------------------


def _strong_password(length: int = 20) -> str:
    symbols = "!@#$%^&*-_=+?"
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, symbols]
    alphabet = "".join(pools)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in pw) for pool in pools):
            return pw


async def _change_via_adapter(service: str, username: str, old: str, new: str) -> tuple[bool, str]:
    """서비스별 비번 변경 어댑터. 지금은 데모몰만 지원. 오류 메시지에 비번을 넣지 않는다."""
    if service != DEMO_MALL_NAME:
        return False, "자동 변경 미지원 서비스"
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{DEMO_MALL_API}/change-password",
                                  json={"username": username, "current_password": old, "new_password": new},
                                  headers={"X-Meonjeo-Auto": "1"}, timeout=15)
        if r.status_code == 200 and r.json().get("ok"):
            return True, ""
        return False, f"데모몰 응답 {r.status_code}"
    except Exception as e:  # noqa: BLE001
        return False, f"데모몰 연결 실패 ({type(e).__name__})"


def _next_group_label(used: set[str]) -> str:
    for i in range(26 * 4):
        letter = chr(ord("A") + i % 26) + ("" if i < 26 else str(i // 26))
        label = f"{letter}그룹"
        if label not in used:
            return label
    return f"{uuid.uuid4().hex[:4]}그룹"


async def _auto_change(incident: dict[str, Any]) -> dict[str, Any] | None:
    """urgent 사고에서 해당 서비스/같은 그룹 중 금고에 있고 자동 변경을 지원하는 곳의 비번을 바꾼다."""
    async with _store_lock:
        data = _load()
    svc = next((s for s in data["services"] if s["name"] == incident["service"]), None)
    group = (svc or {}).get("password_group")
    members = [incident["service"]] + _group_members(data, group, exclude=incident["service"])
    targets = [m for m in members if m in AUTO_CHANGE_SUPPORTED and vault.has(m)]
    if not targets:
        return None
    changed, failed, errors = [], [], {}
    for t in targets:
        meta = vault.entry(t) or {}
        old = vault.get_password(t) or ""
        new = _strong_password(20)
        ok, err = await _change_via_adapter(t, meta.get("username", ""), old, new)
        if ok:
            vault.put(t, new, username=meta.get("username", ""), url=meta.get("url", ""), source="auto_change")
            changed.append(t)
            log.info("자동 비번 변경 완료: %s", t)
        else:
            failed.append(t)
            errors[t] = err
            log.warning("자동 비번 변경 실패: %s (%s) - 기존 비번 유지", t, err)
        del old, new
    return {"changed": changed, "failed": failed, "errors": errors,
            "manual": [m for m in members if m not in changed], "at": _kst_hhmm()}


def _apply_auto_result(data: dict[str, Any], incident: dict[str, Any], auto: dict[str, Any]) -> None:
    """자동 변경 결과를 할 일/그룹에 반영 (비번 원문 없음)."""
    for t in auto["changed"]:
        for a in data["actions"]:
            if a["incident_id"] != incident["id"] or a["done"]:
                continue
            if a["title"] == f"{t} 비밀번호 변경" or a["title"].startswith(f"{t} 비밀번호도 변경"):
                a["done"] = True
                a["completed_at"] = _iso()
                a["detail"] += f" ✅ 먼저지킴이 자동 변경 완료 ({auto['at']}). 새 비번은 내 PC에서 show_password.py로 확인하세요."
        # 이제 다른 비번이므로 혼자 쓰는 새 꼬리표로
        svc = next((s for s in data["services"] if s["name"] == t), None)
        if svc:
            used = {s.get("password_group") for s in data["services"] if s.get("password_group")}
            svc["password_group"] = _next_group_label(used)
    incident["auto_change"] = dict(auto)


async def _process_new_incident(incident_id: str, preventive: list[str]) -> dict[str, Any]:
    """새 사고 공통 처리: (urgent면) 자동 변경 → 알림 → 결과. 비밀번호 원문은 어디에도 싣지 않는다."""
    async with _store_lock:
        incident = next(i for i in _load()["incidents"] if i["id"] == incident_id)
    auto = None
    if incident.get("severity") == "urgent":
        try:
            auto = await _auto_change(incident)
        except Exception as e:  # noqa: BLE001
            log.warning("자동 변경 처리 오류: %s", type(e).__name__)
    async with _store_lock:
        data = _load()
        incident = next(i for i in data["incidents"] if i["id"] == incident_id)
        if auto:
            _apply_auto_result(data, incident, auto)
        pending = [a for a in data["actions"] if a["incident_id"] == incident_id and not a["done"]]
        svc = next((s for s in data["services"] if s["name"] == incident["service"]), None)
        level = incident.get("severity", "normal")
        status = await _send_alert(_alert_text(incident, len(pending), preventive, auto),
                                   priority=SEVERITY[level][2], click=_change_password_url(svc))
        incident["last_alert_at"] = _iso()
        _save(data)
    return {
        "incident_id": incident["id"], "service": incident["service"], "source": incident["source"],
        "title": incident["title"], "severity": level, "severity_label": _severity_label(level),
        "severity_reasons": incident.get("severity_reasons", []),
        "confirmed_items": incident["leaked_items"], "preventive_items": preventive,
        "links": incident["links"][:3], "actions_created": len(incident.get("action_ids", [])),
        "pending_actions": len(pending),
        "auto_change": incident.get("auto_change"),
        "notify": status,
    }


async def _send_reminders() -> int:
    """urgent 사고에 미완료 할 일이 있으면 REMIND_INTERVAL_MIN마다 다시 알린다."""
    sent = 0
    async with _store_lock:
        data = _load()
        for inc in data["incidents"]:
            if inc.get("severity") != "urgent" or inc.get("resolved"):
                continue
            pending = [a for a in data["actions"] if a["incident_id"] == inc["id"] and not a["done"]]
            if not pending:
                continue
            last = inc.get("last_alert_at")
            if last and _now() - datetime.fromisoformat(last) < timedelta(minutes=REMIND_INTERVAL_MIN):
                continue
            svc = next((s for s in data["services"] if s["name"] == inc["service"]), None)
            text = (f"{_severity_label('urgent')} 다시 알려요: {inc['service']} 유출 대응 할 일 {len(pending)}개가 남았어요.\n"
                    + "\n".join(f"- {a['title']}" for a in pending[:5])
                    + f"\n사고 ID: {inc['id']}")
            await _send_alert(text, priority="urgent", click=_change_password_url(svc))
            inc["last_alert_at"] = _iso()
            sent += 1
        if sent:
            _save(data)
    return sent


# ---------------------------------------------------------------------------
# 크롬 비번 CSV 가져오기 (비번은 금고로만, 요약만 출력)
# ---------------------------------------------------------------------------

DOMAIN_SERVICE_MAP: list[tuple[list[str], str, str]] = [
    (["coupang"], "쿠팡", "쇼핑"),
    (["baemin"], "배민", "배달"),
    (["tworld", "sktelecom"], "SKT", "통신사"),
    (["11st"], "11번가", "쇼핑"),
    (["netflix"], "넷플릭스", "기타"),
    (["localhost", "127.0.0.1"], DEMO_MALL_NAME, "쇼핑"),
]
_SECOND_LEVEL = {"co", "or", "go", "ne", "ac", "com", "net"}


def _service_from_url(url: str, fallback: str) -> tuple[str, str, str | None]:
    host = (urlparse(url if "://" in (url or "") else f"https://{url}").hostname or "").lower()
    if host in ("localhost", "127.0.0.1"):
        return DEMO_MALL_NAME, "쇼핑", "localhost"
    labels = re.sub(r"^www\.", "", host).split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL:
        domain = ".".join(labels[-3:])
    else:
        domain = ".".join(labels[-2:]) if host else None
    for keys, name, category in DOMAIN_SERVICE_MAP:
        if any(k in host for k in keys):
            return name, category, domain
    return (domain or fallback or "알 수 없음"), "기타", domain


def import_password_csv(path: str | Path) -> dict[str, Any]:
    """크롬 CSV(name,url,username,password,note) → 서비스 등록 + 금고 저장 + 같은 비번 그룹 지정.
    반환값/로그에 비밀번호 원문은 없다. (서버 안에서는 호출 측이 _store_lock을 잡는다)"""
    rows: dict[str, dict[str, Any]] = {}
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if not row.get("password"):
                continue
            name, category, domain = _service_from_url(row.get("url") or "", row.get("name") or "")
            rows[name] = {"category": category, "domain": domain, "row": row}
    for name, r in rows.items():
        row = r.pop("row")
        vault.put(name, row["password"], username=row.get("username") or "", url=row.get("url") or "",
                  source="import")

    data = _load()
    by_key = {_norm(s["name"]): s for s in data["services"]}
    for name, r in rows.items():
        svc = by_key.get(_norm(name))
        if svc:
            svc["domain"] = r["domain"] or svc.get("domain")
            svc["updated_at"] = _iso()
        else:
            svc = {"id": _new_id("svc"), "name": name, "category": r["category"], "password_group": None,
                   "stored_info": CATEGORY_STORED_INFO[r["category"]], "domain": r["domain"],
                   "registered_at": _iso()}
            data["services"].append(svc)
            by_key[_norm(name)] = svc

    # 같은 비번(지문)끼리 묶어서 꼬리표 지정 - 금고 전체 기준
    clusters: dict[str, list[str]] = {}
    for service, fp in vault.fingerprints().items():
        clusters.setdefault(fp, []).append(service)
    vault_names = {_norm(n) for members in clusters.values() for n in members}
    used = {s["password_group"] for s in data["services"]
            if s.get("password_group") and _norm(s["name"]) not in vault_names}
    shared = []
    for members in sorted(clusters.values(), key=lambda m: (-len(m), m)):
        label = _next_group_label(used)
        used.add(label)
        for m in members:
            if _norm(m) in by_key:
                by_key[_norm(m)]["password_group"] = label
        if len(members) >= 2:
            shared.append({"group": label, "services": members})
    _save(data)

    shared_count = sum(len(g["services"]) for g in shared)
    detail = "; ".join(f"{g['group']}: {', '.join(g['services'])}" for g in shared)
    message = f"서비스 {len(rows)}개 등록, 같은 비번 그룹 {len(shared)}개" + (f" ({detail})" if detail else "")
    return {"services": len(rows), "service_names": list(rows), "shared_groups": shared,
            "shared_service_count": shared_count, "message": message}


async def _downloads_watch() -> None:
    """다운로드 폴더에 새 '*assword*.csv'가 생기면 자동으로 가져오고 원본을 지운다.
    서버 시작 전부터 있던 파일은 건드리지 않는다."""
    if not DOWNLOADS_DIR.exists():
        log.info("다운로드 폴더 없음 → 감시 안 함: %s", DOWNLOADS_DIR)
        return
    seen = {p.name for p in DOWNLOADS_DIR.iterdir()}
    retries: dict[str, int] = {}
    log.info("다운로드 폴더 감시 시작: %s (%s)", DOWNLOADS_DIR, DOWNLOADS_PATTERN)
    while True:
        await asyncio.sleep(3)
        try:
            for p in list(DOWNLOADS_DIR.iterdir()):
                if p.name in seen or not fnmatch.fnmatch(p.name.lower(), DOWNLOADS_PATTERN):
                    continue
                size = p.stat().st_size
                await asyncio.sleep(1)
                if not p.exists() or p.stat().st_size != size:
                    continue  # 아직 쓰는 중
                try:
                    async with _store_lock:
                        summary = await asyncio.to_thread(import_password_csv, p)
                    for _ in range(10):  # 백신 검사 등으로 잠깐 잠겨 있을 수 있음
                        try:
                            p.unlink()
                            break
                        except PermissionError:
                            await asyncio.sleep(1)
                    retries.pop(p.name, None)
                    log.info("자동 가져오기 완료, 원본 삭제: %s (%s)", p.name, summary["message"])
                    await _send_alert(
                        f"📥 서비스 {summary['services']}개 가져왔어요. 같은 비번 {summary['shared_service_count']}곳 발견\n"
                        + summary["message"], priority="default", tags="inbox_tray")
                except PermissionError as e:  # 파일이 잠겨 있음 → 다음 주기에 다시
                    retries[p.name] = retries.get(p.name, 0) + 1
                    log.warning("자동 가져오기 대기(잠김 %d회): %s (%s)", retries[p.name], p.name, e)
                    if retries[p.name] >= 10:
                        seen.add(p.name)
                except Exception as e:  # noqa: BLE001
                    seen.add(p.name)  # 같은 파일로 무한 재시도 방지
                    log.warning("자동 가져오기 실패: %s (%s: %s)", p.name, type(e).__name__, e)
        except Exception as e:  # noqa: BLE001
            log.warning("다운로드 감시 오류: %s", type(e).__name__)


# ---------------------------------------------------------------------------
# 감시 로직
# ---------------------------------------------------------------------------


async def _run_check(days: int) -> dict[str, Any]:
    async with _check_lock:
        days = max(1, min(int(days), 365))
        since = _now() - timedelta(days=days)
        errors: list[str] = []
        notes: list[str] = []

        async with _store_lock:
            services = list(_load()["services"])
        if not services:
            return {"checked_services": 0, "new_incidents": [], "updated_incidents": [], "errors": [],
                    "notes": ["등록된 서비스가 없어요. register_services로 먼저 등록하세요."]}

        candidates: list[dict[str, Any]] = []  # {service, source, key, title, links, leaked_items, published_at}

        async with httpx.AsyncClient(follow_redirects=True) as client:
            # --- 소스 A: 구글 뉴스 RSS ---
            for svc in services:
                articles: dict[str, dict[str, Any]] = {}
                for q in (f"{svc['name']} 개인정보 유출", f"{svc['name']} 해킹"):
                    items, err = await _search_google_news(client, q)
                    if err:
                        errors.append(err)
                    for it in items:
                        title = _strip_html(it["title"])
                        desc = _strip_html(it["description"])
                        text = f"{title} {desc}"
                        if not _has_breach_signal(text):
                            continue
                        if _norm(svc["name"]) not in _norm(text):
                            continue
                        try:
                            pub = parsedate_to_datetime(it["pubDate"])
                        except (TypeError, ValueError):
                            continue
                        if pub < since:
                            continue
                        link = it["link"]
                        if link:
                            articles[link] = {"title": title, "desc": desc, "link": link, "pub": pub,
                                              "press": it.get("press", "")}
                if articles:
                    arts = sorted(articles.values(), key=lambda a: a["pub"], reverse=True)
                    leaked: list[str] = []
                    for a in arts:
                        for item in _extract_leak_items(f"{a['title']} {a['desc']}"):
                            if item not in leaked:
                                leaked.append(item)
                    candidates.append({
                        "service": svc["name"], "source": "google_news", "key": None,
                        "title": arts[0]["title"], "links": [a["link"] for a in arts],
                        "press": sorted({a["press"] for a in arts if a["press"]}),
                        "leaked_items": leaked, "published_at": _iso(arts[0]["pub"]),
                    })

            # --- 소스 B: Have I Been Pwned ---
            breaches, err = await _fetch_hibp(client)
            if err:
                errors.append(err)
            for b in breaches:
                try:
                    added = datetime.fromisoformat(str(b.get("AddedDate", "")).replace("Z", "+00:00"))
                except ValueError:
                    continue
                if added.tzinfo is None:
                    added = added.replace(tzinfo=timezone.utc)
                if added < since:
                    continue
                b_keys = {_norm(b.get("Name", "")), _norm(b.get("Title", "")), _norm(b.get("Domain", ""))}
                b_keys.discard("")
                for svc in services:
                    if not (_service_keys(svc) & b_keys):
                        continue
                    leaked = []
                    for dc in b.get("DataClasses", []):
                        mapped = HIBP_CLASS_MAP.get(dc)
                        if mapped and mapped not in leaked:
                            leaked.append(mapped)
                    candidates.append({
                        "service": svc["name"], "source": "hibp", "key": b.get("Name"),
                        "title": f"{b.get('Title')} 유출 ({b.get('BreachDate')}, {b.get('PwnCount', 0):,}건)",
                        "links": [f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}"],
                        "leaked_items": leaked, "data_classes": b.get("DataClasses", []),
                        "published_at": _iso(added),
                    })

        # --- 중복 제거 & 저장 ---
        new_incidents: list[dict[str, Any]] = []
        updated: list[str] = []
        async with _store_lock:
            data = _load()
            seen_links = set(data["seen"]["links"])
            seen_hibp = set(data["seen"]["hibp"])
            for c in candidates:
                if c["source"] == "hibp":
                    if c["key"] in seen_hibp:
                        continue
                    seen_hibp.add(c["key"])
                else:
                    fresh = [l for l in c["links"] if l not in seen_links]
                    if not fresh:
                        continue
                    seen_links.update(fresh)
                    c["links"] = fresh
                    # 같은 서비스의 진행 중인 뉴스 사고가 기간 내에 있으면 거기에 기사만 붙인다
                    existing = next((i for i in data["incidents"]
                                     if i["service"] == c["service"] and i["source"] == "google_news"
                                     and not i.get("resolved")
                                     and datetime.fromisoformat(i["detected_at"]) >= since), None)
                    if existing:
                        existing["links"].extend(fresh)
                        existing["press"] = sorted(set(existing.get("press", [])) | set(c.get("press", [])))
                        _apply_severity(existing)
                        new_items = [i for i in c["leaked_items"] if i not in existing["leaked_items"]]
                        if new_items:  # 새로 확인된 항목 → 예방 조치를 확인 조치로 올림
                            existing["leaked_items"].extend(new_items)
                            existing["items_confirmed"] = True
                            _sync_actions(data, existing)
                        updated.append(existing["id"])
                        continue
                incident = {
                    "id": _new_id("inc"),
                    "service": c["service"],
                    "source": c["source"],
                    "title": c["title"],
                    "links": c["links"],
                    "leaked_items": c["leaked_items"],
                    "items_confirmed": bool(c["leaked_items"]),
                    "data_classes": c.get("data_classes", []),
                    "press": c.get("press", []),
                    "published_at": c["published_at"],
                    "detected_at": _iso(),
                    "resolved": False,
                }
                _apply_severity(incident)
                data["incidents"].append(incident)
                _sync_actions(data, incident)
                svc = next((s for s in data["services"] if s["name"] == incident["service"]), None)
                incident["_preventive"] = _item_basis(incident, svc)[1]  # 알림용 (저장 전 제거)
                new_incidents.append(incident)
            preventive_by_id = {i["id"]: i.pop("_preventive") for i in new_incidents}
            data["seen"]["links"] = sorted(seen_links)[-5000:]
            data["seen"]["hibp"] = sorted(seen_hibp)
            _save(data)

        # --- 알림 ---
        results = []
        for inc in new_incidents:
            results.append(await _process_new_incident(inc["id"], preventive_by_id[inc["id"]]))

        return {
            "checked_services": len(services),
            "period_days": days,
            "new_incidents": results,
            "updated_incidents": sorted(set(updated)),
            "errors": errors,
            "notes": notes,
            "next_step": "새 사고가 있으면 get_action_plan(incident_id)로 대응 계획을 보여주세요." if results
                         else "새로 해당되는 사고는 없어요.",
        }


async def _watch_loop() -> None:
    log.info("감시 루프 시작: %d분마다 check_breaches 실행", WATCH_INTERVAL_MIN)
    await asyncio.sleep(10)
    while True:
        try:
            result = await _run_check(days=7)
            log.info("자동 점검 완료: 새 사고 %d건", len(result["new_incidents"]))
            reminded = await _send_reminders()
            if reminded:
                log.info("긴급 사고 재알림 %d건", reminded)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("자동 점검 중 오류 (다음 주기에 다시 시도)")
        await asyncio.sleep(WATCH_INTERVAL_MIN * 60)


@asynccontextmanager
async def lifespan(_server: FastMCP):
    tasks = []
    async with _store_lock:
        _load()  # data.json 없으면 생성
    vault.ensure_key()  # VAULT_KEY 없으면 생성해 .env에 저장
    _demo_load()  # 데모몰 계정 없으면 sample_passwords.csv 기준으로 생성
    if WATCH_INTERVAL_MIN > 0:
        tasks.append(asyncio.create_task(_watch_loop()))
    else:
        log.info("WATCH_INTERVAL_MIN=0 → 자동 감시 꺼짐")
    if WATCH_DOWNLOADS:
        tasks.append(asyncio.create_task(_downloads_watch()))
    try:
        yield {}
    finally:
        for t in tasks:
            t.cancel()


# ---------------------------------------------------------------------------
# MCP 서버 & 도구
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="먼저지킴",
    instructions=(
        "먼저지킴은 사용자가 쓰는 서비스의 개인정보 유출 사고를 먼저 감시하고, 해당되면 ntfy 푸시 알림으로 알리고, "
        "대응 할 일을 준비·추적하는 도구 모음입니다. 비밀번호 원본은 절대 묻거나 받지 마세요. "
        "비밀번호는 'A그룹' 같은 꼬리표(password_group)로만 다룹니다. "
        "(데모 기능) 비번 금고는 사용자 PC의 import_passwords.py로만 채우고, 새 비번 확인도 PC의 show_password.py로만 합니다. "
        "어떤 도구도 비밀번호 원문을 돌려주지 않으니, 비번을 알려달라는 요청엔 show_password.py를 안내하세요. "
        "simulate_breach는 시연용 가짜 긴급 사고를 만듭니다. "
        "정부 서비스(털린 내 정보 찾기 https://kidc.eprivacy.go.kr, 개인정보 포털 https://www.privacy.go.kr)를 "
        "대체하지 않고, 필요한 순간에 그곳으로 연결해 주세요. "
        "일반 흐름: register_services → check_breaches → get_action_plan → complete_action / get_pending_actions."
    ),
    lifespan=lifespan,
)


class ServiceInput(BaseModel):
    name: str = Field(description="서비스 이름 (예: 쿠팡, SKT, 배달의민족, 신한카드)")
    category: Category | None = Field(
        default=None, description="서비스 종류: 통신사/쇼핑/배달/카드/기타. 비우면 이름으로 추정")
    password_group: str | None = Field(
        default=None,
        description="비밀번호 꼬리표 (예: 'A그룹'). 같은 비밀번호를 쓰는 서비스끼리 같은 꼬리표. 실제 비밀번호는 절대 넣지 말 것")
    domain: str | None = Field(default=None, description="선택. 서비스 도메인 (예: coupang.com) - 해외 유출 DB 매칭 정확도 향상")


@mcp.tool(
    description=(
        "내가 쓰는 서비스를 등록/갱신합니다. 사용자가 '쿠팡이랑 SKT 써', '이 사이트들 등록해줘', "
        "'e프라이버시 클린서비스 목록 붙여넣을게' 처럼 쓰는 서비스를 알려줄 때 사용하세요.\n"
        "- services: [{name, category(통신사/쇼핑/배달/카드/기타), password_group}] 목록. category를 비우면 이름으로 추정합니다.\n"
        "- password_group: 같은 비밀번호를 쓰는 서비스끼리 묶는 꼬리표(예: 'A그룹', 'B그룹'). "
        "실제 비밀번호는 절대 묻지도 넣지도 마세요. 비밀번호처럼 보이는 값은 저장을 거부합니다.\n"
        "- bulk_text: e프라이버시 클린서비스(본인확인 내역)에서 복사한 가입 사이트 목록 텍스트를 그대로 붙여넣으면 "
        "서비스명을 뽑아 한 번에 등록합니다.\n"
        "종류별로 보통 맡기는 정보(전화번호, 주소, 카드, 이메일 등)를 stored_info로 자동 추정해 저장하며, "
        "이미 있는 서비스는 갱신합니다. 결과에는 안 쓰는 사이트 탈퇴(개인정보 포털) 안내가 포함됩니다."
    ),
)
async def register_services(
    services: list[ServiceInput] | None = None,
    bulk_text: str | None = None,
) -> dict[str, Any]:
    try:
        incoming: list[dict[str, Any]] = [s.model_dump() for s in (services or [])]
        parsed_from_bulk = _parse_bulk_text(bulk_text) if bulk_text else []
        incoming += [{"name": p["name"], "category": None, "password_group": None, "domain": p.get("domain")}
                     for p in parsed_from_bulk]
        if not incoming:
            return {"ok": False, "message": "등록할 서비스가 없어요. services 또는 bulk_text를 주세요.", "tip": PORTAL_TIP}

        added, updated, warnings = [], [], []
        async with _store_lock:
            data = _load()
            by_key = {_norm(s["name"]): s for s in data["services"]}
            for item in incoming:
                name = (item.get("name") or "").strip()
                if not name:
                    continue
                group = (item.get("password_group") or "").strip() or None
                if group and _looks_like_password(group):
                    warnings.append(f"{name}: password_group 값이 실제 비밀번호처럼 보여 저장하지 않았어요. "
                                    "'A그룹' 같은 꼬리표만 써주세요.")
                    group = None
                category = item.get("category") or _guess_category(name)
                existing = by_key.get(_norm(name))
                if existing:
                    if item.get("category"):
                        existing["category"] = category
                        existing["stored_info"] = CATEGORY_STORED_INFO[category]
                    if group:
                        existing["password_group"] = group
                    if item.get("domain"):
                        existing["domain"] = item["domain"]
                    existing["updated_at"] = _iso()
                    updated.append(existing)
                else:
                    svc = {
                        "id": _new_id("svc"),
                        "name": name,
                        "category": category,
                        "password_group": group,
                        "stored_info": CATEGORY_STORED_INFO[category],
                        "domain": item.get("domain"),
                        "registered_at": _iso(),
                    }
                    data["services"].append(svc)
                    by_key[_norm(name)] = svc
                    added.append(svc)
            _save(data)
            total = len(data["services"])

        def brief(s: dict[str, Any]) -> dict[str, Any]:
            return {"name": s["name"], "category": s["category"], "password_group": s.get("password_group"),
                    "stored_info": s["stored_info"]}

        return {
            "ok": True,
            "added": [brief(s) for s in added],
            "updated": [brief(s) for s in updated],
            "parsed_from_bulk_text": [p["name"] for p in parsed_from_bulk],
            "warnings": warnings,
            "total_services": total,
            "tip": PORTAL_TIP,
        }
    except Exception as e:  # noqa: BLE001
        log.exception("register_services 오류")
        return {"ok": False, "message": f"등록 중 오류: {e}", "tip": PORTAL_TIP}


@mcp.tool(
    description=(
        "등록된 내 서비스 목록을 보여줍니다. '내가 등록한 서비스 뭐 있어?', '어디 어디 감시 중이야?' 같은 질문이나, "
        "다른 도구를 쓰기 전에 현재 상태를 확인할 때 사용하세요. "
        "각 서비스의 종류, 비밀번호 꼬리표(password_group), 맡긴 정보 추정(stored_info), 진행 중 사고 수를 돌려줍니다."
    ),
)
async def list_my_services() -> dict[str, Any]:
    async with _store_lock:
        data = _load()
    open_by_service: dict[str, int] = {}
    for inc in data["incidents"]:
        if not inc.get("resolved"):
            open_by_service[inc["service"]] = open_by_service.get(inc["service"], 0) + 1
    services = [{
        "name": s["name"], "category": s["category"], "password_group": s.get("password_group"),
        "stored_info": s["stored_info"], "domain": s.get("domain"),
        "open_incidents": open_by_service.get(s["name"], 0),
        "in_vault": vault.has(s["name"]),
        "auto_change_supported": s["name"] in AUTO_CHANGE_SUPPORTED,
    } for s in data["services"]]
    return {"count": len(services), "services": services,
            "password_reuse_warnings": _reuse_warnings(data),
            "tip": PORTAL_TIP if services else "아직 등록된 서비스가 없어요. register_services로 등록하세요."}


@mcp.tool(
    description=(
        "내가 쓰는 서비스에 최근 개인정보 유출·해킹 사고가 있는지 지금 바로 점검합니다. "
        "'쿠팡 털렸대?', '요즘 유출 사고 있어?', '점검해줘' 같은 요청이나 정기 점검에 사용하세요. "
        "(서버가 백그라운드에서 주기적으로도 자동 실행합니다.)\n"
        "- 소스 A: 구글 뉴스 RSS에서 '{서비스명} 개인정보 유출', '{서비스명} 해킹'을 검색해 기간 내 유출·해킹·침해 기사를 찾습니다.\n"
        "- 소스 B: Have I Been Pwned 공개 유출 목록에서 서비스 이름/도메인이 일치하고 기간 내 추가된 사고를 찾습니다.\n"
        "이미 본 기사/사고는 다시 처리하지 않습니다. 새 사고가 생기면 대응 할 일을 자동으로 만들고 ntfy 푸시 알림을 보냅니다. "
        "days: 최근 며칠 이내 사고만 볼지 (기본 7일)."
    ),
)
async def check_breaches(days: int = 7) -> dict[str, Any]:
    try:
        return await _run_check(days)
    except Exception as e:  # noqa: BLE001
        log.exception("check_breaches 오류")
        return {"ok": False, "message": f"점검 중 오류가 났지만 서버는 정상이에요: {e}"}


@mcp.tool(
    description=(
        "특정 유출 사고(incident_id)에 대해 지금 해야 할 대응 계획을 보여줍니다. "
        "check_breaches에서 새 사고가 나왔거나, 사용자가 '쿠팡 유출됐는데 뭐 해야 돼?', '대응 방법 알려줘'라고 할 때 사용하세요.\n"
        "포함 내용: 해당 서비스 비밀번호 변경 안내와 같은 비밀번호 꼬리표(password_group)를 쓰는 다른 서비스(같이 바꿔야 할 곳), "
        "털린 내 정보 찾기 조회(https://kidc.eprivacy.go.kr), 유출 항목별 조치(전화번호→명의도용방지서비스, 카드→카드사 분실신고, "
        "유심→통신사 유심보호서비스, 주소→택배 사칭 문자 주의), 할 일 목록과 완료 여부, "
        "가족에게 보낼 주의 문자 초안, 피해 발생 시 고객센터 보상 요청문 초안.\n"
        "뉴스 사고는 기사에서 확인된 유출 항목(items.confirmed)에 그 서비스에 맡긴 정보(items.preventive)도 합쳐 대비합니다. "
        "각 할 일의 basis가 '확인됨'(유출 확인, 먼저), '기본'(늘 하는 일), '예방'(맡긴 정보라 미리 대비)이니, "
        "사용자에게 보여줄 때 확인된 것과 예방 차원을 꼭 구분해서 설명하세요."
    ),
)
async def get_action_plan(incident_id: str) -> dict[str, Any]:
    async with _store_lock:
        data = _load()
    incident = next((i for i in data["incidents"] if i["id"] == incident_id), None)
    if not incident:
        recent = [{"incident_id": i["id"], "service": i["service"], "title": i["title"]}
                  for i in data["incidents"][-5:]]
        return {"ok": False, "message": f"사고 {incident_id}를 찾을 수 없어요.", "recent_incidents": recent}

    svc = next((s for s in data["services"] if s["name"] == incident["service"]), None)
    group = (svc or {}).get("password_group")
    confirmed, preventive = _item_basis(incident, svc)
    actions = [{"action_id": a["id"], "title": a["title"], "detail": a["detail"], "link": a["link"],
                "basis": a.get("basis", BASIS_DEFAULT), "items": a.get("items", []), "done": a["done"]}
               for a in data["actions"] if a["incident_id"] == incident_id]
    basis_order = {BASIS_CONFIRMED: 0, BASIS_DEFAULT: 1, BASIS_PREVENTIVE: 2}
    actions.sort(key=lambda a: basis_order.get(a["basis"], 1))
    name = incident["service"]
    if confirmed and preventive:
        items_note = (f"기사에서 확인된 유출은 {_j(', '.join(confirmed), '이에요/예요')}. "
                      f"{_j(', '.join(preventive), '은/는')} 확인되진 않았지만 "
                      f"{name}에 맡긴 정보라 예방 차원으로 같이 대비했어요.")
    elif confirmed:
        items_note = f"확인된 유출 항목({', '.join(confirmed)}) 기준으로 대비했어요."
    else:
        items_note = (f"유출 항목은 아직 확인되지 않았어요. {name}에 맡긴 정보({', '.join(preventive)}) 기준으로 "
                      "예방 차원에서 대비했어요.")
    return {
        "ok": True,
        "incident": {
            "incident_id": incident["id"], "service": incident["service"], "source": incident["source"],
            "title": incident["title"], "links": incident["links"][:5], "article_count": len(incident["links"]),
            "published_at": incident.get("published_at"),
        },
        "severity": {
            "level": incident.get("severity", "normal"),
            "label": _severity_label(incident.get("severity", "normal")),
            "reasons": incident.get("severity_reasons") or _severity(incident)[1],
        },
        "auto_change": incident.get("auto_change"),
        "change_password_link": _change_password_url(svc),
        "items": {
            "confirmed": confirmed,
            "preventive": preventive,
            "note": items_note,
        },
        "basis_legend": {BASIS_CONFIRMED: "유출이 확인된 항목에 대한 조치 (먼저 하세요)",
                         BASIS_DEFAULT: "유출 항목과 상관없이 늘 하는 일",
                         BASIS_PREVENTIVE: "확인은 안 됐지만 맡긴 정보라 미리 대비 (여유 있을 때)"},
        "password": {
            "change_now": incident["service"],
            "password_group": group,
            "same_group_services": _group_members(data, group, exclude=incident["service"]),
            "note": "같은 꼬리표 서비스는 같은 비밀번호일 가능성이 높아 함께 바꾸세요." if group
            else "비밀번호 꼬리표가 없어요. register_services로 password_group을 지정하면 같이 바꿀 곳을 알려드려요.",
        },
        "must_do": f"털린 내 정보 찾기에서 계정 유출 여부 조회 ({LINK_KIDC})",
        "actions": actions,
        "progress": f"{sum(a['done'] for a in actions)}/{len(actions)} 완료",
        "drafts": {
            "family_message": _family_draft(incident, confirmed),
            "compensation_request": _compensation_draft(incident, confirmed + preventive),
        },
        "official_links": {"털린 내 정보 찾기": LINK_KIDC, "개인정보 포털": LINK_PORTAL, "명의도용방지서비스": LINK_MSAFER},
    }


@mcp.tool(
    description=(
        "대응 할 일 하나를 완료 처리합니다. 사용자가 '비번 바꿨어', '명의도용방지 가입했어', '다 했어'처럼 "
        "어떤 할 일을 끝냈다고 말할 때 사용하세요. action_id는 get_action_plan 또는 get_pending_actions 결과에 있습니다. "
        "한 사고의 할 일을 모두 끝내면 그 사고는 해결됨으로 표시됩니다."
    ),
)
async def complete_action(action_id: str) -> dict[str, Any]:
    async with _store_lock:
        data = _load()
        action = next((a for a in data["actions"] if a["id"] == action_id), None)
        if not action:
            return {"ok": False, "message": f"할 일 {action_id}를 찾을 수 없어요. get_pending_actions로 확인하세요."}
        already = action["done"]
        action["done"] = True
        action["completed_at"] = action["completed_at"] or _iso()
        siblings = [a for a in data["actions"] if a["incident_id"] == action["incident_id"]]
        remaining = [a for a in siblings if not a["done"]]
        incident = next((i for i in data["incidents"] if i["id"] == action["incident_id"]), None)
        if incident and not remaining:
            incident["resolved"] = True
            incident["resolved_at"] = _iso()
        _save(data)
    return {
        "ok": True,
        "completed": action["title"],
        "already_done": already,
        "incident_id": action["incident_id"],
        "remaining_for_incident": [{"action_id": a["id"], "title": a["title"]} for a in remaining],
        "message": "이 사고 대응을 모두 마쳤어요. 수고했어요!" if not remaining else f"남은 할 일 {len(remaining)}개",
    }


@mcp.tool(
    description=(
        "아직 끝내지 않은 대응 할 일 전체를 사고별로 보여줍니다. '뭐 남았어?', '할 일 알려줘', "
        "'대응 어디까지 했지?' 같은 질문이나, 사용자에게 진행 상황을 상기시킬 때 사용하세요."
    ),
)
async def get_pending_actions() -> dict[str, Any]:
    async with _store_lock:
        data = _load()
    incidents = {i["id"]: i for i in data["incidents"]}
    grouped: dict[str, dict[str, Any]] = {}
    for a in data["actions"]:
        if a["done"]:
            continue
        inc = incidents.get(a["incident_id"], {})
        g = grouped.setdefault(a["incident_id"], {
            "incident_id": a["incident_id"], "service": a["service"], "title": inc.get("title"), "actions": []})
        g["actions"].append({"action_id": a["id"], "title": a["title"], "detail": a["detail"], "link": a["link"],
                             "basis": a.get("basis", BASIS_DEFAULT)})
    basis_order = {BASIS_CONFIRMED: 0, BASIS_DEFAULT: 1, BASIS_PREVENTIVE: 2}
    for g in grouped.values():
        g["actions"].sort(key=lambda x: basis_order.get(x["basis"], 1))
    total = sum(len(g["actions"]) for g in grouped.values())
    return {"total_pending": total, "by_incident": list(grouped.values()),
            "message": "남은 할 일이 없어요." if total == 0 else f"남은 할 일 {total}개"}


@mcp.tool(
    description=(
        "비밀번호를 '진짜 바꿔야 할 때만' 알려주는 조언입니다. 주기적 변경을 강요하지 않습니다. "
        "'비번 바꿔야 할 거 있어?', '비밀번호 정리 좀 해줘' 같은 요청에 사용하세요.\n"
        "판단 기준: (1) 해결 안 된 유출 사고가 난 서비스와 같은 비밀번호 꼬리표(password_group)를 쓰는 서비스 → 최우선, "
        "(2) 같은 꼬리표를 2개 이상 서비스가 함께 쓰는 경우(한 곳이 털리면 연쇄 위험) → 권장. "
        "각 대상에 이유를 붙여 돌려줍니다. 비밀번호 원본은 다루지 않습니다."
    ),
)
async def get_password_advice() -> dict[str, Any]:
    async with _store_lock:
        data = _load()
    services = data["services"]
    open_incidents = [i for i in data["incidents"] if not i.get("resolved")]
    auto_changed = {n for i in open_incidents for n in (i.get("auto_change") or {}).get("changed", [])}
    breached = {i["service"] for i in open_incidents} - auto_changed
    groups: dict[str, list[str]] = {}
    for s in services:
        if s.get("password_group"):
            groups.setdefault(s["password_group"], []).append(s["name"])

    urgent, recommended = [], []
    covered: set[str] = set()
    for inc in open_incidents:  # 자동 변경 후 남은 같은 비번 서비스
        auto = inc.get("auto_change") or {}
        manual = [m for m in auto.get("manual", []) if m not in auto_changed and m != inc["service"]]
        if auto.get("changed") and manual:
            covered.update(manual)
            urgent.append({
                "password_group": next((s.get("password_group") for s in services if s["name"] == manual[0]), None),
                "services": manual,
                "reason": f"{inc['service']} 유출 사고 때 같은 비번을 쓰던 곳이에요. {_j('·'.join(auto['changed']), '은/는')} "
                          f"자동으로 바꿨지만, 같은 비번을 {len(manual)}곳에서 아직 쓰고 있어요. 직접 바꿔주세요.",
            })
    for group, members in groups.items():
        if set(members) <= covered:
            continue
        hit = [m for m in members if m in breached]
        if hit:
            urgent.append({
                "password_group": group, "services": members,
                "reason": f"{', '.join(hit)}에 유출 사고가 있었고, 같은 꼬리표({group})라 같은 비밀번호일 수 있어요. "
                          "지금 바꾸고, 서로 다른 비밀번호로 나눠주세요.",
            })
        elif len(members) >= 2:
            recommended.append({
                "password_group": group, "services": members,
                "reason": f"같은 비번을 {len(members)}곳에서 쓰고 있어요 ({group}). 한 곳만 털려도 나머지가 연쇄로 위험해요. "
                          "여유 있을 때 중요한 곳(통신사·카드·쇼핑)부터 따로 바꾸세요.",
            })
    no_group_breached = [n for n in breached
                         if not next((s for s in services if s["name"] == n and s.get("password_group")), None)]
    for n in no_group_breached:
        urgent.append({"password_group": None, "services": [n],
                       "reason": f"{n}에 유출 사고가 있어요. 이 서비스 비밀번호는 바꾸세요. "
                                 "같은 비밀번호를 쓰는 곳이 있다면 꼬리표를 지정해 알려주세요."})

    return {
        "urgent": urgent,
        "recommended": recommended,
        "message": ("지금 꼭 바꿔야 할 곳은 없어요. 주기적으로 바꿀 필요는 없고, 사고가 나면 먼저 알려드릴게요."
                    if not urgent and not recommended else
                    "진짜 바꿔야 할 곳만 골랐어요. 정기 변경은 필요 없어요."),
        "password_reuse_warnings": _reuse_warnings(data),
        "tip": f"내 계정이 유출 DB에 있는지는 털린 내 정보 찾기에서 확인할 수 있어요 ({LINK_KIDC})",
    }


@mcp.tool(
    description=(
        "[시연용] 뉴스 없이 가짜 '긴급(urgent)' 유출 사고를 만들어 전체 대응 흐름을 바로 실행합니다. "
        "사용자가 '데모 보여줘', '데모몰 유출 시뮬레이션 해줘', '자동 비번 변경 시연'처럼 요청할 때만 사용하세요. "
        "흐름: 사고 생성(유출 항목: 비밀번호·이메일·전화번호) → 대응 할 일 생성 → 해당 서비스나 같은 비번 그룹 중 "
        "금고에 있고 자동 변경을 지원하는 곳(지금은 데모몰)의 비번을 20자 랜덤 비번으로 실제 변경 → ntfy 긴급 알림. "
        "새 비번은 응답에 절대 포함되지 않습니다. 확인은 사용자 PC에서 'python show_password.py 데모몰'로 안내하세요. "
        "service는 등록된 서비스 이름이어야 합니다 (예: 데모몰)."
    ),
)
async def simulate_breach(service: str) -> dict[str, Any]:
    try:
        async with _store_lock:
            data = _load()
            svc = next((s for s in data["services"] if _norm(s["name"]) == _norm(service)), None)
            if not svc:
                return {"ok": False, "message": f"'{service}'는 등록된 서비스가 아니에요. 등록된 서비스: "
                                                + ", ".join(s["name"] for s in data["services"])}
            incident = {
                "id": _new_id("inc"),
                "service": svc["name"],
                "source": "simulation",
                "title": f"[데모] {svc['name']} 개인정보 유출 (시뮬레이션)",
                "links": [],
                "leaked_items": ["비밀번호", "이메일", "전화번호"],
                "items_confirmed": True,
                "data_classes": [],
                "press": [],
                "published_at": _iso(),
                "detected_at": _iso(),
                "resolved": False,
            }
            _apply_severity(incident)
            data["incidents"].append(incident)
            _sync_actions(data, incident)
            preventive = _item_basis(incident, svc)[1]
            _save(data)
        result = await _process_new_incident(incident["id"], preventive)
        result["ok"] = True
        result["next_step"] = ("get_action_plan으로 남은 할 일을 보여주세요. 새 비번은 사용자 PC에서 "
                               "'python show_password.py " + svc["name"] + "'로만 확인할 수 있어요.")
        return result
    except Exception as e:  # noqa: BLE001
        log.exception("simulate_breach 오류")
        return {"ok": False, "message": f"시뮬레이션 중 오류: {type(e).__name__}"}


# ---------------------------------------------------------------------------
# 데모몰 웹 화면 / API (테스트용 가짜 쇼핑몰)
# ---------------------------------------------------------------------------

_DEMO_CSS = """
:root{--bg:#f6f7fb;--card:#fff;--ink:#1d2433;--muted:#667085;--brand:#ff5a36;--ok:#12b76a;--bad:#f04438}
@media (prefers-color-scheme: dark){:root{--bg:#12141a;--card:#1c1f27;--ink:#eef0f5;--muted:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,'Malgun Gothic',sans-serif}
main{max-width:520px;margin:40px auto;padding:0 16px}.card{background:var(--card);border-radius:16px;padding:24px;box-shadow:0 2px 12px #0001;margin-bottom:16px}
h1{margin:0 0 4px;font-size:22px}h1 span{color:var(--brand)}.muted{color:var(--muted);font-size:14px}
.big{font-size:28px;font-weight:700;margin:8px 0}label{display:block;font-size:14px;margin:12px 0 4px}
input{width:100%;padding:10px;border-radius:10px;border:1px solid #8884;background:transparent;color:inherit;font-size:15px}
button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:10px;background:var(--brand);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
nav a{color:var(--brand);margin-right:12px;text-decoration:none;font-size:14px}#msg{margin-top:12px;font-weight:600}
"""


def _demo_page(title: str, body: str, refresh: bool = False) -> HTMLResponse:
    meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    return HTMLResponse(
        f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{meta}<title>{html.escape(title)}</title>
<style>{_DEMO_CSS}</style></head><body><main>
<div class="card"><h1>🛍️ <span>데모몰</span></h1><div class="muted">먼저지킴 시연용 가짜 쇼핑몰 (진짜 쇼핑몰 아님)</div>
<nav style="margin-top:12px"><a href="/demo-mall">내 계정</a><a href="/demo-mall/login">로그인</a>
<a href="/demo-mall/change-password">비밀번호 변경</a></nav></div>{body}</main></body></html>""")


_DEMO_FORM_JS = """
<script>
async function send(e, url, fields){
  e.preventDefault(); const f=e.target, body={};
  fields.forEach(k=>body[k]=f.elements[k].value);
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json(); const m=document.getElementById('msg');
  m.textContent=j.message; m.style.color=j.ok?'var(--ok)':'var(--bad)'; if(j.ok) f.reset();
}
</script>"""


@mcp.custom_route("/demo-mall", methods=["GET"])
async def demo_mall_home(_request: Request) -> HTMLResponse:
    acct = _demo_load()
    changed = datetime.fromisoformat(acct["changed_at"]).astimezone(KST)
    mins = int((_now() - datetime.fromisoformat(acct["changed_at"])).total_seconds() // 60)
    ago = "방금 전" if mins < 1 else f"{mins}분 전" if mins < 60 else f"{mins // 60}시간 전"
    body = f"""<div class="card"><div class="muted">계정</div><div>{html.escape(acct['username'])}</div>
<div class="muted" style="margin-top:16px">마지막 비밀번호 변경</div>
<div class="big">{changed:%Y-%m-%d %H:%M}</div><div class="muted">{ago} · {html.escape(acct['changed_by'])}</div>
<div class="muted" style="margin-top:16px">비밀번호는 화면에 표시하지 않아요. 이 페이지는 5초마다 새로고침돼요.</div></div>"""
    return _demo_page("데모몰 - 내 계정", body, refresh=True)


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


@mcp.custom_route("/demo-mall/login", methods=["GET", "POST"])
async def demo_mall_login(request: Request):
    if request.method == "GET":
        return _demo_page("데모몰 - 로그인", """<div class="card"><h2>로그인</h2>
<form onsubmit="send(event,'/demo-mall/login',['username','password'])">
<label>이메일</label><input name="username" autocomplete="username">
<label>비밀번호</label><input name="password" type="password" autocomplete="current-password">
<button>로그인</button><div id="msg"></div></form></div>""" + _DEMO_FORM_JS)
    b = await _json_body(request)
    if _demo_verify(b.get("username", ""), b.get("password", "")):
        return JSONResponse({"ok": True, "message": "로그인 성공! 환영해요."})
    return JSONResponse({"ok": False, "message": "이메일 또는 비밀번호가 틀렸어요."}, status_code=401)


@mcp.custom_route("/demo-mall/change-password", methods=["GET", "POST"])
async def demo_mall_change_password(request: Request):
    if request.method == "GET":
        return _demo_page("데모몰 - 비밀번호 변경", """<div class="card"><h2>비밀번호 변경</h2>
<form onsubmit="send(event,'/demo-mall/change-password',['username','current_password','new_password'])">
<label>이메일</label><input name="username" autocomplete="username">
<label>현재 비밀번호</label><input name="current_password" type="password" autocomplete="current-password">
<label>새 비밀번호 (12자 이상)</label><input name="new_password" type="password" autocomplete="new-password">
<button>변경하기</button><div id="msg"></div></form></div>""" + _DEMO_FORM_JS)
    b = await _json_body(request)
    if not _demo_verify(b.get("username", ""), b.get("current_password", "")):
        return JSONResponse({"ok": False, "message": "현재 비밀번호가 틀렸어요."}, status_code=401)
    new = b.get("new_password") or ""
    if len(new) < 12:
        return JSONResponse({"ok": False, "message": "새 비밀번호는 12자 이상이어야 해요."}, status_code=400)
    by = "먼저지킴 자동 변경" if request.headers.get("x-meonjeo-auto") == "1" else "직접 변경"
    _demo_set_password(new, by)
    return JSONResponse({"ok": True, "message": "비밀번호를 바꿨어요."})


@mcp.custom_route("/.well-known/change-password", methods=["GET"])
async def well_known_change_password(_request: Request) -> RedirectResponse:
    return RedirectResponse("/demo-mall/change-password", status_code=302)


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "server": "먼저지킴", "watch_interval_min": WATCH_INTERVAL_MIN})


if __name__ == "__main__":
    mcp.run(transport="http", host=HOST, port=PORT, path="/mcp")

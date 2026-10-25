# 먼저지킴 MCP 서버

개인정보 유출 사고를 **먼저** 감시하고, 내가 쓰는 서비스가 해당되면 [ntfy](https://ntfy.sh) 푸시로 **먼저** 알리고,
대응 할 일을 준비·추적하는 에이전트용 MCP 서버입니다. (FastMCP, **Streamable HTTP**)

- MCP 도구는 비밀번호 원본을 받지도, 돌려주지도 않습니다. 비밀번호는 `A그룹` 같은 **꼬리표**로만 다룹니다.
  (꼬리표 자리에 비밀번호처럼 보이는 값이 들어오면 저장을 거부합니다.)
- **[데모] 비번 금고**: 내 PC의 `import_passwords.py`로만 채우고(Fernet 암호화, `vault.json`), `show_password.py`로만 확인합니다.
- 정부 서비스(털린 내 정보 찾기, 개인정보 포털)를 대체하지 않고, 필요한 순간에 연결해주는 허브입니다.

## 도구

| 도구 | 하는 일 |
|---|---|
| `register_services(services, bulk_text)` | 서비스 등록/갱신. 종류별 맡긴 정보(stored_info) 자동 추정. e프라이버시 클린서비스 목록 붙여넣기 지원 |
| `list_my_services()` | 등록된 서비스 + 진행 중 사고 수 |
| `check_breaches(days=7)` | 구글 뉴스 RSS + Have I Been Pwned (둘 다 키 불필요)로 유출 점검 → 새 사고면 할 일 생성 + ntfy 푸시 알림 |
| `get_action_plan(incident_id)` | 비번 변경(같은 꼬리표 서비스 포함), 털린 내 정보 찾기, 항목별 조치, 가족 문자/보상 요청문 초안 |
| `complete_action(action_id)` | 할 일 완료 처리 (모두 끝나면 사고 해결) |
| `get_pending_actions()` | 남은 할 일 사고별 정리 |
| `get_password_advice()` | "진짜 바꿔야 할 때만" 비번 변경 대상과 이유 + "같은 비번을 N곳에서 쓰고 있어요" 경고 |
| `simulate_breach(service)` | **[시연용]** 뉴스 없이 긴급 사고를 만들어 자동 비번 변경·알림 흐름을 바로 실행 |

### 심각도
| 단계 | 기준 | ntfy Priority |
|---|---|---|
| 🔴긴급 `urgent` | 기간 내 기사 10건 이상, 또는 유출 항목에 비밀번호·주민등록번호·유심 | urgent |
| 🟠위험 `high` | 기사 5~9건, 또는 서로 다른 언론사 3곳 이상 | high |
| 🟡주의 `normal` | 그 외 | default |

- 긴급 사고에 미완료 할 일이 남아 있으면 감시 루프마다 `REMIND_INTERVAL_MIN`(기본 60분) 간격으로 다시 알립니다.
- 알림을 누르면 `https://{domain}/.well-known/change-password`(비번 변경 표준 주소)로 이동합니다.

## 데모 순서 (자동 비번 변경)

> 시연용 기능입니다. 데모몰은 이 서버 안의 가짜 쇼핑몰이고, `sample_passwords.csv`의 계정은 전부 가짜입니다.

1. 서버 켜기: `python server.py` → 브라우저로 `http://127.0.0.1:8000/demo-mall` 열어두기 (5초마다 새로고침)
2. 폰 ntfy 앱에서 `NTFY_TOPIC` 구독
3. **크롬 비번 가져오기**: `sample_passwords.csv`를 다운로드 폴더에 복사
   (실제로는 크롬 설정 → 비밀번호 관리자 → 비밀번호 내보내기 → `Chrome Passwords.csv`)
   → 몇 초 안에 자동으로 가져오고 원본 CSV는 삭제 → 📥 "서비스 6개 가져왔어요. 같은 비번 3곳 발견" 알림
   - 손으로 하려면: `python import_passwords.py <csv경로>` (샘플 파일은 지우지 않음)
4. vooy에서 "내 서비스 보여줘" → `list_my_services`에 "같은 비번을 3곳에서 쓰고 있어요 (A그룹: 데모몰, 배민, 쿠팡)"
5. vooy에서 "데모몰 유출 시뮬레이션 해줘" → `simulate_breach("데모몰")`
   → 🔴긴급 "데모몰 유출 감지 → 비번 자동 변경 완료 (HH:MM). 새 비번은 금고에서 확인하세요. 같은 비번을 쓰던 배민·쿠팡은 직접 바꿔주세요"
   → 데모몰 화면의 "마지막 비밀번호 변경" 시각이 방금으로 바뀜 (먼저지킴 자동 변경)
6. 내 PC 터미널에서 새 비번 확인: `python show_password.py 데모몰`
7. `http://127.0.0.1:8000/demo-mall/login`에서 그 비번으로 로그인 → "로그인 성공!"
8. 데모 다시 하기 전 초기화: 서버를 끄고 `data.json`, `vault.json`, `demo_mall.json`을 지운 뒤 다시 켜기
   (데모몰 비번이 `sample_passwords.csv` 값으로 돌아감)

보안 메모
- 새 비번은 MCP 도구 응답, 서버 로그, ntfy 알림 어디에도 나오지 않습니다 (ntfy는 공개 채널).
- `VAULT_KEY`(.env)와 `vault.json`이 둘 다 있으면 비번을 풀 수 있으니, 두 파일 모두 공유·커밋 금지입니다 (.gitignore 처리됨).
- 다운로드 폴더 감시는 서버가 켜진 **뒤에 새로 생긴** `*assword*.csv`만 처리합니다. 원래 있던 파일은 건드리지 않습니다.
- 자동 변경은 지금 데모몰만 지원합니다. 다른 서비스는 "직접 바꿔야 해요" 목록으로 안내합니다.

- 엔드포인트: `http://<host>:8000/mcp` (Streamable HTTP)
- 헬스체크: `GET /health`
- 저장: `data.json` (없으면 자동 생성) — services / incidents / actions + 이미 본 기사·사고 기록
- 감시 루프: 서버 시작 10초 후 첫 점검, 이후 `WATCH_INTERVAL_MIN`분마다 `check_breaches(7)` 자동 실행

## 실행 방법

```bash
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env          # macOS/Linux: cp .env.example .env  → 값 채우기
python server.py
```

`Uvicorn running on http://0.0.0.0:8000` 이 보이면 준비 완료입니다.

### 환경변수 (.env)

| 이름 | 설명 |
|---|---|
| `NTFY_TOPIC` | ntfy 토픽 이름 (예: `meonjeo-sua-1025`). 없으면 알림만 건너뜀 |
| `NTFY_SERVER` | 선택. 자체 ntfy 서버 주소 (기본 `https://ntfy.sh`) |
| `WATCH_INTERVAL_MIN` | 자동 감시 주기(분), 기본 60. `0`이면 자동 감시 끔 |
| `USER_NAME` | 알림/초안에 쓸 이름 (예: 수아) |
| `HOST`, `PORT`, `DATA_FILE` | 선택. 기본 `0.0.0.0`, `8000`, `./data.json` |

알림 받기: 폰에 ntfy 앱(Android/iOS)을 설치하고 `NTFY_TOPIC`과 같은 토픽을 구독하세요. 브라우저로 `https://ntfy.sh/<토픽>`에 들어가도 됩니다.
ntfy.sh 공개 토픽은 이름을 아는 사람 누구나 구독할 수 있으니, 남이 추측하기 어려운 이름을 쓰세요.

알림 테스트만 따로 해보려면:

```bash
curl -H "Priority: high" -H "Tags: rotating_light" -d "먼저지킴 테스트" https://ntfy.sh/<토픽>
```

## vooy 연결

vooy는 원격에서 접속하므로 서버가 인터넷에서 닿아야 합니다.

1. 서버를 클라우드(Render, Railway, Fly.io, VPS 등)에 올리거나, 로컬이면 터널을 엽니다.
   ```bash
   ngrok http 8000
   ```
2. vooy의 MCP 서버 추가 화면에서 URL에 `https://<주소>/mcp` 입력 (전송 방식: Streamable HTTP).
3. 도구 7개가 보이면 연결 완료.

> 클라우드에 올릴 때는 `data.json`이 재배포 때 지워지지 않도록 영구 디스크 경로를 `DATA_FILE`로 지정하세요.
> 이 서버에는 인증이 없으니 주소를 외부에 공유하지 마세요.

## 로컬 테스트 방법

터미널 1:
```bash
python server.py
```

터미널 2 — 도구 목록 → `register_services` → `check_breaches` → `get_action_plan` → `complete_action`
→ 중복 처리 확인 → 비밀번호 거부 확인 → `get_pending_actions` → `get_password_advice` 순서로 실제 호출합니다.
```bash
python test_client.py
```

다른 주소로 테스트하려면 `python test_client.py https://<주소>/mcp`.

테스트 데이터가 실제 `data.json`에 섞이지 않게 하려면 서버를 `DATA_FILE=test.json`으로 띄우세요.
`test_client.py`는 HIBP에 실제로 등록된 최근 사고(Crunchbase, 2026-10-14 추가)를 매칭 확인용으로 등록합니다.
시간이 지나 30일 범위를 벗어나면 새 사고가 0건으로 나올 수 있는데, 정상입니다.

MCP Inspector로 GUI 확인도 가능합니다:
```bash
npx @modelcontextprotocol/inspector
```
→ Transport `Streamable HTTP`, URL `http://127.0.0.1:8000/mcp`.

## 판단 기준 메모

- **구글 뉴스 RSS(소스 A)**: `"{서비스명} 개인정보 유출"`, `"{서비스명} 해킹"`을 검색해 제목/요약에 `유출·해킹·침해` + 서비스명이 있고 기간 내 기사. 같은 서비스의 진행 중 뉴스 사고가 있으면
  새 기사는 그 사고에 붙입니다 (알림 폭탄 방지). 유출 항목은 키워드로 추출하고, "카드번호는 유출 안 돼" 같은 부정문은 제외합니다.
  "해킹은 아니라지만"처럼 유출·해킹 키워드 자체가 부정된 기사도 사고로 보지 않습니다.
  구글 뉴스 RSS의 description은 제목+언론사뿐이라, 유출 항목은 사실상 제목에서만 추출됩니다.
- **확인 vs 예방**: 뉴스 사고는 기사에서 확인된 유출 항목에 그 서비스에 맡긴 정보(stored_info)를 합쳐 대비합니다.
  할 일마다 `basis`가 붙습니다 — `확인됨`(유출 확인, 먼저), `기본`(늘 하는 일), `예방`(맡긴 정보라 미리 대비).
  예방 조치는 더 가볍게 안내합니다 (예: 카드 → 분실신고 대신 결제 알림·이상 결제 확인).
  이후 기사에서 항목이 새로 확인되면 예방 조치가 확인 조치로 자동 승격됩니다.
  HIBP 사고는 유출 항목이 정확하므로 확인된 항목만 씁니다.
  항목이 확인되지 않으면 그 서비스에 보통 맡기는 정보 기준으로 대비합니다.
- **HIBP(소스 B)**: `Name/Title/Domain`이 서비스 이름·도메인·별칭(쿠팡→coupang 등)과 일치하고 `AddedDate`가 기간 내.
  HIBP는 영문 이름이라, 한국 서비스는 `domain`을 함께 등록하면 매칭이 정확해집니다.
- 외부 API가 실패해도 결과의 `errors`에 담기고 서버는 계속 동작합니다.

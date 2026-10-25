"""로컬 테스트: 도구 목록 확인 → register_services → check_breaches → get_action_plan.

사용법:
    python server.py            # 다른 터미널에서 서버 실행
    python test_client.py       # 기본 http://127.0.0.1:8000/mcp
    python test_client.py https://내서버주소/mcp
"""

import asyncio
import json
import sys

from fastmcp import Client

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/mcp"


def show(title: str, result) -> dict:
    data = result.data if result.data is not None else result.structured_content
    print(f"\n=== {title} ===")
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return data


async def main() -> None:
    async with Client(URL) as client:
        tools = await client.list_tools()
        print("=== 도구 목록 ===")
        for t in tools:
            print(f"- {t.name}")

        show("register_services", await client.call_tool("register_services", {
            "services": [
                {"name": "쿠팡", "category": "쇼핑", "password_group": "A그룹"},
                {"name": "SKT", "category": "통신사", "password_group": "B그룹"},
                {"name": "배달의민족", "password_group": "A그룹"},
                # HIBP 매칭 확인용 (2026-10-14 HIBP에 추가된 실제 사고)
                {"name": "Crunchbase", "category": "기타", "password_group": "A그룹"},
            ],
            "bulk_text": "1\t11번가\twww.11st.co.kr\t2023.05.01\n2\t무신사\twww.musinsa.com\t2024.01.10",
        }))

        check = show("check_breaches", await client.call_tool("check_breaches", {"days": 30}))

        incidents = check.get("new_incidents") or []
        if incidents:
            plan = show("get_action_plan", await client.call_tool(
                "get_action_plan", {"incident_id": incidents[0]["incident_id"]}))
            show("complete_action", await client.call_tool(
                "complete_action", {"action_id": plan["actions"][0]["action_id"]}))
        else:
            print("\n(새 사고가 없어 get_action_plan은 건너뜀)")

        again = show("check_breaches (재실행: 중복이면 새 사고 0건)",
                     await client.call_tool("check_breaches", {"days": 30}))
        print("중복 처리 OK" if not again["new_incidents"] else "!! 중복 사고가 다시 생겼어요")

        guard = show("register_services (비번처럼 보이는 꼬리표 거부)", await client.call_tool(
            "register_services", {"services": [{"name": "쿠팡", "password_group": "Qwer1234!"}]}))
        print("비번 거부 OK" if guard["warnings"] else "!! 비번이 저장됐어요")

        show("get_pending_actions", await client.call_tool("get_pending_actions", {}))
        show("get_password_advice", await client.call_tool("get_password_advice", {}))


if __name__ == "__main__":
    asyncio.run(main())

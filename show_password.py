"""금고에 저장된 비밀번호 확인 (내 PC 터미널 전용).

사용법:
    python show_password.py 데모몰

MCP 도구로 만들지 않은 이유: 에이전트(vooy) 대화 기록에 비밀번호가 남으면 안 되기 때문.
화면 공유 중이라면 실행 전에 주의하세요.
"""

import sys

sys.stdout.reconfigure(encoding="utf-8")

import vault  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        print("금고에 있는 서비스:", ", ".join(vault.services()) or "(비어 있음)")
        sys.exit(1)
    name = sys.argv[1]
    password = vault.get_password(name)
    if password is None:
        print(f"'{name}'은(는) 금고에 없어요. 금고에 있는 서비스: {', '.join(vault.services()) or '(비어 있음)'}")
        sys.exit(1)
    meta = vault.entry(name) or {}
    print(f"서비스  : {meta.get('service', name)}")
    print(f"아이디  : {meta.get('username', '')}")
    print(f"비밀번호: {password}")
    print(f"갱신    : {meta.get('updated_at', '')} ({meta.get('source', '')})")


if __name__ == "__main__":
    main()

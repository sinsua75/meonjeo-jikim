"""크롬 비밀번호 CSV 가져오기 (내 PC 전용).

사용법:
    python import_passwords.py "C:\\Users\\나\\Downloads\\Chrome Passwords.csv"
    python import_passwords.py sample_passwords.csv          # 샘플은 지우지 않음
    python import_passwords.py 파일.csv --keep                # 원본 CSV를 남기고 싶을 때

- 도메인으로 서비스명/종류를 추정해 data.json에 등록 (domain 포함)
- 비밀번호는 Fernet으로 암호화해 vault.json에만 저장, 같은 비번끼리 A그룹·B그룹… 자동 지정
- 화면에는 요약만 출력 (비밀번호는 출력하지 않음)
- 끝나면 원본 CSV 삭제 (평문 비번 파일을 남기지 않기 위해)
"""

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

from server import SAMPLE_CSV, import_password_csv  # noqa: E402


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(1)
    path = Path(args[0]).expanduser().resolve()
    if not path.exists():
        print(f"파일이 없어요: {path}")
        sys.exit(1)
    summary = import_password_csv(path)
    print(summary["message"])
    keep = "--keep" in sys.argv or path == SAMPLE_CSV.resolve()
    if keep:
        print("원본 CSV는 남겨뒀어요." if path != SAMPLE_CSV.resolve() else "샘플 파일이라 지우지 않았어요.")
    else:
        path.unlink()
        print("평문 비번이 담긴 원본 CSV를 삭제했어요.")


if __name__ == "__main__":
    main()

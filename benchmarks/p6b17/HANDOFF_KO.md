# RISU Probe P6-B17 독립 출처 검증 핸드오프

작성: 2026-11-12
상태: B17 원본 증거, 교차 감사, 변조 대조군, Ubuntu/Windows/macOS 회귀 모두 검증 완료
브랜치: qualification/p6b17-independent-source-provenance-20261112

## 핵심
B15는 명시적 사용자 계약과 실제 MCP/상태 증거의 불일치를 찾았다.
B16은 같은 MCP 세션에서 광고한 완전한 카탈로그와 JSON outputSchema만
강한 출처 근거로 사용하고 readOnlyHint는 참고 정보로 유지했다.
B17은 원본 GitHub 저장소의 커밋, Git 트리 blob, 정적 소스 outputSchema,
동시대 tools/list, 원본 tools/call 결과를 독립적으로 대조한다.

새 명령: risu-probe verify-mcp-origin
소스: src/risu_mcp_origin.py
동결 Git blob: 75180de2dbd78165d2e970ee15e99df14804e7f1
기존 B16 blob: be24472b0fea8d8e7a252a7a36158cf8873128de
기존 B15 blob: 4314e9bf92e2ec75c421bab25eae3b43f1424a08

## 외부 검증
새로운 개발 조직: GoogleCloudPlatform/mcp-python-sdk-grpc-poc
고정 커밋: cedc20fdc8fdf22fc8b411a3947ae03c71cbc926
고정 파일: examples/servers/structured_output_lowlevel.py
고정 blob: 7f102ff8b5e09b6df64b6b9c0fd913ac25f709f5
GitHub API로 커밋 서명 상태 Verified / valid 확인.
동일 파일의 원격 Git 트리 객체와 격리 환경 체크아웃의 Git blob 일치.
MCP 원본 서버를 stdio로 실행하여 get_weather 도구 2회 정상.
두 원본 결과 모두 소스 outputSchema 및 tools/list와 일치.

원본 서버 실행: https://github.com/risu-research/risu-probe/actions/runs/43300343923
별도 독립 감사: https://github.com/risu-research/risu-probe/actions/runs/43300940842
전체 회귀: https://github.com/risu-research/risu-probe/actions/runs/43299820956

기존 B16 원본 출처 대조군:
https://github.com/risu-research/risu-probe/actions/runs/43301252255
AI-Shell-Team/aish: source-corroborated pass 2, 미승격 2
MarvinRomson/master-mcp: 미승격 2

실제 외부 신규 버그 확정: 0개. 정상 서버의 소스 출처 일관성을 검증한 성과다.

## 별도 합성/변조 검사
원본 서버 출력을 변경하지 않고 첫 실행 보존. 그 후 독립적으로:
- 소스 worktree 변경 -> Git blob과 불일치, 거부
- 소스 SHA 핀 위조 -> 거부
- GitHub 원격 트리 증거 위조 -> 별도 독립 감사에서 거부
- tools/list의 스키마를 임의로 변경 -> SOURCE_CATALOG_CONFLICT 격리 2개
- 정상 humidity 정수 값을 임의로 문자열로 변경 -> SOURCE_CORROBORATED_MISMATCH 1개
위 두 마지막 경우는 합성 검사이며 실제 외부 버그로 계산 금지.

## 재현
전체 GitHub 연구 브랜치를 checkout한다. 네트워크로 타사 소스 버전을
새로 선택하지 말고, 위의 정확한 커밋을 사용한다.

1) python -m pip install .
2) risu-probe verify-mcp-origin --help
3) 원본 evidence에서 original_stdio.jsonl과 contract.json을 선택한다.
4) 원본 저장소를 지정된 커밋으로 독립 checkout한다.
5) benchmarks/p6b17/GCP_PINNED_SOURCE_MANIFEST.json을 지정해 검증한다.
6) docs/P6B17_INDEPENDENT_CONTRACT_ORIGIN_AUDIT.md의 감사 범위 및
   GitHub CI 로그와 체크섬을 확인한다.

## 증거 경계
- GitHub의 유효한 서명 상태는 '발행된 Git 커밋'의 출처 근거를 강화한다.
- 실제 MCP 서버 프로세스가 반드시 해당 소스로 빌드되었다는 실행 바이너리
  원격 증명까지 얻은 것은 아니다.
- outputSchema의 정적 리터럴만 좁게 확인한다. 동적 생성 스키마는 보류.
- 행위 권한은 readOnlyHint나 소스 설명만으로 증명하지 않는다.
- 이 코호트는 소스를 보고 선정했다. 맹검 신규 결함 발견 성공률 주장은 불가.
- 이번 실험은 legacy MCP 2025-11-25 스타일. MCP 2026-07-28 stateless
  프로토콜의 완전한 지원이라고 주장하지 않는다.

## 다음 B18
가능하면 외부에 검증 가능한 signed build provenance / release provenance와
원본 MCP 실행을 연결한다. 별도 선정된 실제 버그의 수정 전후 코드와 정상
대조군을 선고정한 뒤 새 탐지기를 독립 평가한다. 미확인 출처는 미확인으로 남긴다.

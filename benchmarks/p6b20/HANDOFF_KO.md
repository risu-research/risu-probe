# RISU Probe P6-B20 범용 실행 효과 판정 연구 핸드오프

기준 날짜: 2026-11-12
상태: B19 개발용 양성 대조군 재현 PASS, 새로운 외부 개발 조직 원본 2회 재현 PASS,
     독립 파일 바이트 감사 PASS, 회귀 Ubuntu/Windows/macOS 모두 PASS
브랜치: qualification/p6b20-generic-effect-boundaries-20261112
변경 방침: main과 이전 B15-B19 연구 결과를 유지. 자동 머지/출시 금지.

## 1. 핵심 알고리즘
새 오프라인 명령어: risu-probe verify-mcp-effects
구현: src/risu_mcp_effects.py
고정 Git blob: ab8191a3ca153ac079fcd07d128ddfcd7a06e99f

B19 전용 Git 도구 이름, core.fsmonitor, GHSA 번호, 버전명 등을
알고리즘 소스에서 제거하고 모든 원본 MCP 도구에 공통인 효과를 본다.

사전에 고정한 2 x 2 평가 설계:
                 Trigger 조건    정상 Control
기준 실행(before)      BT             BC
대조 실행(after)       AT             AC

각 칸에는 원본 MCP tools/list와 도구 요청/응답, 별도 관측자의
측정 전/후 증거 파일이 포함된다. 각 JSON 필드의 포인터와 원본 파일
SHA256을 별도로 연결하고, 도구명, 인자 해시, 응답 해시, JSON-RPC
원본 트레이스 전체 해시 및 요청-응답 라인 번호를 함께 검증한다.

측정 타입:
- boolean: 파일 존재/상태 flag 변화
- digest: 파일 내용 SHA-256, 없으면 null
- counter: 정수 개수/바이트 수 변화

효과 변화 D = (pre != post)를 각 칸에서 개별 계산한다.
판정 규칙은 소프트웨어 실행 전에 고정하며 다음을 지원한다.
- 수정 효과 억제: [1,0,0,0]
- 정상적인 쓰기 효과 유지: [1,0,1,0]
- 모든 조건에서 무변화: [0,0,0,0]
- 임의로 사전에 확정한 네 칸의 boolean truth table

MCP 응답 JSON 본문 해시가 네 칸에서 모두 같지만,
관측된 외부 부작용을 수정판에서 억제하는 패턴인 경우
응답만 봐서는 알 수 없는 효과 차이로 표시한다.

보안 정책의 정당성은 별도 근거가 필요하다.
실제 변화가 있었다고 자동으로 '무단 효과'라고 판정하지 않는다.
MCP readOnlyHint만으로 권한 의무를 인증하지 않는다.

## 2. B19 이전 연구, 개발용 양성 대조군으로 고정
원본 보안 권고: GHSA-6hqx-gqrx-c5r2 (이미 공개된 결함).
공식 외부 서명 PyPI mcp-server-git 2026.11.4 / 2026.11.11.
B19 CI: 43316866530, 43317961883.
원본 응답 4개, 합성 저장소의 실행 부작용 기록 모두 그대로 보존.
B20은 이 증거를 공통 boolean 효과 센서 양식으로 변환했다.

결과: 수정 후 부작용 억제 [1,0,0,0] = PASS.
네 MCP 응답 본문 완전 동일 = PASS.
응답만으로 부작용 탐지가 어렵다는 관측 = PASS.
새로운 취약점 발견으로 세지 않음.

B20 B19 개발 전용 재검증:
https://github.com/risu-research/risu-probe/actions/runs/43321811071

## 3. 이전에 보지 않은 다른 개발 조직의 실제 원본 서버
다른 외부 조직 소스: kujirahand/mcp_server-filesystem
정확한 Git commit: 1aff1e094ed317ec2c5de06591978781d660c48a
원본 src/filesystem_mcp/server.py Git blob:
f886fcbc6e61f3be8e6fd76b6e5f3ad1f8cbb7b6
공개 PyPI 패키지: filesystem-mcp 1.0.2
원본 wheel SHA256:
94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235
실제 소스 server.py SHA256:
c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8

원본 GitHub 파일과 PyPI wheel의 소스 바이트, 실제 설치된
Python 모듈이 일치했다. 이 패키지에는 별도 PyPI 서명 증명을
확인하지 않았으므로 서명된 배포물이라고 주장하지 않는다.

개발셋과 동일한 판정 알고리즘을 고정한 상태에서, 원본
write_file 도구를 실제 MCP stdio로 실행했다.
매번 파일 위치가 다른 임시 허용 디렉터리에서 아래 네 실험:
BT: 새 파일 쓰기 -> 파일 등장, 내용 해시 변화, 크기 0에서 30
BC: 기존 같은 내용 덮어쓰기 -> 논리적 내용/크기 변화 없음
AT: 동일 소프트웨어의 다른 실행에서 새 파일 쓰기 -> 세 변화 발생
AC: 동일 소프트웨어의 다른 실행에서 같은 내용 덮어쓰기 -> 변화 없음

주의: FS 평가의 before/after는 1.0.2 '같은 버전의 독립 반복'이다.
수정 전/후 보안 패치가 아니다. 평가 목표는 범용 효과 알고리즘의
Git 도구 이외의 정상 동작에 대한 독립 전이 가능성이다.

3개 센서 모두 [1,0,1,0] 규칙과 일치, 원본 4회 성공.
MCP 응답은 실행별 임시 파일 경로가 달라 동일하지 않았다.
알고리즘은 MCP 응답이 같을 것을 요구하지 않았고, 상태 변화는 정확했다.

최초 실험:
https://github.com/risu-research/risu-probe/actions/runs/43322280437
별도 환경에서 새 프로세스 4개 독립 재현:
https://github.com/risu-research/risu-probe/actions/runs/43322884796

실제 외부 소스 원본 write_file 호출 8건.
각 원본 실행의 실제 파일 바이트를 저장했고 다른 감사기로 다시
해싱해 증거 정합성을 확인했다.
파일 바이트와 관측 JSON 변조 대조군은 모두 거부됐다.

## 4. 테스트와 품질
기존 전체 테스트와 B20 신규 32개 합성·비정상 입력 시험을 포함해
381개 테스트 각각 Ubuntu/Windows/macOS에서 통과.
https://github.com/risu-research/risu-probe/actions/runs/43321190922

초기 외부 평가 실행 환경의 오류 두 건은 보존됨:
43321966210, 43322117372.
원인은 부모 테스트 프로세스에 RISU 모듈 미설치 및
virtualenv python symlink를 불필요하게 resolve한 실행 경로.
둘 다 외부 서버나 RISU 일반 검사기의 문제는 아니며, 실행
하네스만 수정한 뒤 동일한 고정 규칙으로 재실행했다.

## 5. 재현 지침
소스 파일:
- src/risu_mcp_effects.py
- benchmarks/p6b20/FROZEN_GENERIC_EFFECT_EVALUATION.json
- benchmarks/p6b20/FROZEN_FS_HELDOUT_PLAN.json
- benchmarks/p6b20/adapter_b19_development.py
- benchmarks/p6b20/capture_unseen_filesystem_original.py
- benchmarks/p6b20/independent_non_git_effect_audit.py
- tests/test_p6b20_generic_effects.py

실행 CLI:
risu-probe verify-mcp-effects \
  --plan PLAN.json \
  --evidence-root OBSERVED_CASES \
  --format json --out RESULT.json

재현 자료에는 MCP 통신, 효과 측정 원본 JSON,
실제 저장된 쓰기 전후 파일 내용, 결과 JSON, PyPI 원본 wheel,
소스 출처 검증 기록 및 SHA256 목록 포함.

## 6. 중요한 방법론적 한계
- B20의 상태 검사 자체는 오프라인 JSON을 암호학적으로
  외부 계측자에게 귀속시키지 않는다. CI 원본 관측 및
  독립 재실행이 이번 결과를 별도로 뒷받침한다.
- 이 엔진의 기본 변화 판정은 값의 방향을 구분하지 않는다.
  false->true와 true->false 모두 변경으로 센다.
  원본 값은 보존돼 있지만 일반 엔진의 방향/허가 증명은 다음 연구 과제다.
- 파일 크기/해시/존재 여부는 서로 다른 측정 성질이지만
  같은 한 파일에 대한 결과다. 3개 독립 조직이 아니다.
- 도구가 성공했다고 부작용의 정당성까지 증명되지는 않는다.
- B19 개발 양성 대조군은 새 발견 또는 맹검 성능 지표로 세면 안 된다.
- B20의 외부 파일 서버 평가 또한 소스 확인 후 선정한 정상 동작
  사례이므로 신규 보안 결함을 발견한 실험이 아니다.
- 일반화 가능성이 두 개발조직에서 확인된 것은 제한된
  타입 관측/증거 묶음 수준이다. 인과적 결함 발견 성능으로
  승격하려면 새로운 외부 프로젝트의 진짜 결함 수정 전후를
  규칙을 동결한 다음 독립 재현해야 한다.

## 7. 다음 최선의 방향
방향성이 있는 전이 계약(생성/삭제/증가/감소),
독립 오퍼레이팅 시스템 효과 계측, 외부 권한 출처와
실제 효과를 묶는 최소 증거 certificate를 구현하자.
새 독립 평가셋은 Git/PyPI signed wheel 및 이번 filesystem-mcp
외의 새로운 개발 조직을 사전 등록할 것.

상세 영문 감사/연구보고:
docs/P6B20_GENERIC_NATIVE_EFFECT_EVIDENCE_RESEARCH.md

# RISU Probe P6-B21: 실제 실행 효과의 방향 + 자원 소유자 서명 권한 검증

기준일: 2026-11-12
브랜치: qualification/p6b21-directed-signed-owner-effects-20261112
상태: 구현, 원본 외부 MCP 직접 실행, 독립 서명 검증과 재실행, 교차 운영체제 회귀 PASS
main과 이전 B19/B20 동결 검사기: 변경 없음

## 핵심 목표
B20에서는 파일이 생성되었는지 등 '무엇인가 바뀌었다'는 사실을 검증했다.
B21에서는 ACTIVATE/DEACTIVATE, CREATE/DELETE/REPLACE,
INCREASE/DECREASE의 '변화 방향'을 구별하고, 그 변화가
독립적으로 신뢰한 자원 소유자 서명 정책의 정확한 허용 범위 안에
있는지를 별도로 판단한다.

MCP readOnlyHint나 서버 설명은 접근 권한 증거가 아니다.
공식 MCP 스펙에서도 annotations를 기본적으로 신뢰되지 않은
도구 힌트로 보며, 실제 집행은 별도 권한 계층에서 담당해야 한다.

## 구현
새 CLI:
risu-probe verify-mcp-effect-authority \
  --plan ... \
  --evidence-root ... \
  --authority-manifest ... \
  --trust-root ... \
  --trusted-root-sha256 ... \
  --format json --out ...

제품 코드: src/risu_mcp_effect_authority.py
기반: src/risu_mcp_effects.py (B20의 고정 검사기 변경 없음)

허가 증거:
- Ed25519로 서명한 자원 소유자의 실제 사전 허가 envelope
- 신뢰 루트 public key의 해시를 별도 경로에서 명시적으로 고정
- 발급자 신원 및 리소스 ID의 정확한 일치, wildcard 없음
- 원본 도구 이름, 원본 파라미터 전체 SHA256, 정확한 자원 파라미터
  JSON pointer 및 값 SHA256
- 실제 배포된 원본 소프트웨어 wheel SHA256
- 발급·만료 시간과 원본 실행 타임라인, 고유 nonce
- 관측값 종류별 허용 방향
- 원본 MCP JSON-RPC와 당시 tools/list 및 도구 result
- 실행 전/후 독립 관측 JSON과 파일 SHA256 / 실제 바이트

정책 검증 실패, 출처 불일치, 만료, 서명 위조, 다른 도구/자원에
대한 허가를 가져온 경우 모두 UNVERIFIED로 실패.
진짜 서명된 정책에 반하는 실제 효과가 확인되면
SIGNED_SCOPE_OBSERVED_VIOLATION으로 별도 판정.
신원 모르는 사람의 서명이 유효하다는 이유만으로 허가를 인정하지 않는다.

## 실제 원본 서버
외부 개발 프로젝트: kujirahand/mcp_server-filesystem
정확한 Git commit: 1aff1e094ed317ec2c5de06591978781d660c48a
원본 Git server.py blob:
f886fcbc6e61f3be8e6fd76b6e5f3ad1f8cbb7b6
원본 PyPI 패키지: filesystem-mcp 1.0.2
wheel SHA256:
94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235
원본 실행 서버 모듈 SHA256:
c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8

이는 공개 배포물 및 Git 소스 바이트 일치 검증이며,
외부 개발자가 암호학적으로 서명한 릴리스임을 주장하지 않는다.
외부 개발자가 직접 서명한 공식 수정 전후 비교는 이전 B19에 있음.

## 권한의 실제 출처
이번 실험에서는 사용자가 운영하는 실서비스 권한이 아니라,
CI 테스트 실행자가 자신이 직접 생성·관리하는 임시 로컬
파일을 소유하는 상황을 사용한다.

해당 격리 자원 소유자가 실제 Ed25519 개인키를 새로 생성하고,
공개키 신뢰 루트를 첫 원본 MCP 호출 이전에 고정했으며,
각 원본 호출 전에 정확한 행동 허용 범위에 서명했다.
실제 개인키는 메모리에만 유지하고 다운로드 자료에 넣지 않는다.

다른 독립 GitHub CI 실행 환경에서는 완전히 새로운 개인키와
공개키로 다시 같은 실험을 반복했다. 원본 두 실행의 키가 다르다는
점도 확인했다.

서명은 실제이며 서명 대조는 암호학적이다. 다만 서명 자체가
실서비스 사용자의 법적·OS 수준 권한을 독립 증명하지 않으므로
판정 등급은 CI_LOCAL_FIXTURE_ONLY로 정확히 제한한다.

## 네 가지 실제 원본 MCP 호출
각 실험마다 새로운 격리 파일 경로를 사용, MCP 원본
write_file 요청을 수정 없이 실행하고 실제 파일 바이트를 기록.

1. before_trigger: 파일 없음 -> 29바이트 파일 생성
  변화: ACTIVATE / CREATE / INCREASE(+29)
  사전 서명 허가: 세 변화 모두 허용 -> 3/3 범위 내

2. before_control: 동일한 29바이트 기존 파일 덮어쓰기
  변화: NO_CHANGE / NO_CHANGE / NO_CHANGE
  사전 서명 허가: 세 변화 모두 NO_CHANGE -> 3/3 범위 내

3. after_trigger: 파일 없음 -> 29바이트 생성
  변화: ACTIVATE / CREATE / INCREASE(+29)
  사전 서명 허가: 세 관측 항목 모두 NO_CHANGE만 허용
  결과: 실제 서명된 임시 소유자 정책의 범위에서 3개 위반 검출.
  이 사례는 실험자가 의도적으로 정책과 요청을 다르게 만든
  정상적인 외부 파일 서버 테스트이지, upstream 보안 취약점이 아님.

4. after_control: 67바이트 기존 파일 -> 29바이트 파일
  변화: NO_CHANGE / REPLACE / DECREASE(-38)
  사전 서명 허가: 세 결과 모두 허용 -> 3/3 범위 내

원본 외부 서버의 네 호출은 모두 정상 완료.
서명은 서버가 실행 전에 강제로 집행한 것이 아니라,
나중에 RISU가 실제 관측 결과와 대조한 것임.
이는 post-hoc conformance audit, pre-call prevention 아님.

첫 원본 실행:
https://github.com/risu-research/risu-probe/actions/runs/43327020115

첫 실제 검사 결과:
원본 MCP 4회, 소유자 서명 4/4, 방향·허가 항목 12개,
허용 범위 9개, 범위 위반 3개(모두 한 의도된 케이스),
신규 외부 취약점 0개.

## 완전히 다른 서명키 + 독립 재실행
별도 GitHub Actions에서 새로운 임시 자원 및 독립 서명키를 생성해
원본 패키지 1.0.2를 다시 설치하고 실제 4회 원본 MCP 실행.
독립 검증 프로그램은 RISU B20/B21 검사기를 import하지 않으며,
원본 Ed25519 서명, 실제 전후 파일 바이트, SHA256,
MCP tools/list 및 JSON-RPC 응답, 실행 전 허가 기록을 모두 재확인.

두 번의 독립 실행 총 실제 원본 MCP 호출 8회,
서명된 실행 전 허가 8개, 방향·권한 판정 항목 24개.
두 환경 모두 '허용 9/12, 3/12 범위 위반'으로 동일하게 판정.
서명 위조 및 물리적 파일 바이트 변조를 독립 감사에서 거부.

독립 실행:
https://github.com/risu-research/risu-probe/actions/runs/43327518214

## 전체 기존 기능 회귀
Ubuntu/Windows/macOS 각각 444개 테스트 통과.
https://github.com/risu-research/risu-probe/actions/runs/43326394106

신규 테스트는 원본 관측 파일 위조, 다른 사람의 공개키,
서명 위조, 다른 자원에 대한 허가 재사용, 파라미터 바꿔치기,
재사용된 nonce, 기한 만료, 허가 발급 시점 오류,
잘못된 자원 ID, 증가/감소/생성/삭제/교체/상태 변화 등을 포함한다.

## 매우 중요한 한계
1. 서명자의 실제 소유권은 외부 독립 신뢰 루트로 등록해야 한다.
   이번에는 테스트 실행자가 직접 관리하는 임시 자원이므로
   진짜 고객/기관의 OAuth·자산 소유 증명이 아니다.
2. 에이전트 actor는 요청에서 주장된 신원이며 실제 인증은 별개.
3. 동일한 완전한 원본 증거 ZIP 전체를 재생하는 것은
   전역 nonce 데이터베이스/독립 타임스탬프가 없으면 막을 수 없다.
4. 관측 JSON과 파일 바이트 검증은 CI 증거의 정합성 확인이지
   외부 감사자의 HSM 서명 또는 원격 실행 증명은 아니다.
5. 서명된 정책에 범위를 벗어난다는 것은 사후 판정이지
   MCP 서버가 이미 실행한 코드를 되돌리거나 차단하지 않는다.
6. 이번 외부 원본 서버는 B20에서 사용했던 정상 동작 대상이며
   완전히 새로운 외부 결함 발견 평가가 아니다.
7. 변화가 기록되지 않은 다른 부작용까지 없었다는 증명도 아니다.

## 다음 연구 수준 향상 방향
- 실제 권한자가 사전에 서명한 범위를 MCP 호출 이전에 강제하는
  optional pre-call enforcement gateway
- 외부 고객/자원 소유자 신원 및 키 등록, 만료·취소·회전, 이벤트 nonce 원장
- OS/DAC 및 HTTP OAuth 기반 허가와 관측된 효과를 교차 검증
- 완전히 새 외부 개발 조직의 실제 취약·수정 버전으로 동결 후 맹검 평가

자세한 영문 보고서:
docs/P6B21_OWNER_SIGNED_DIRECTIONAL_EFFECTS.md

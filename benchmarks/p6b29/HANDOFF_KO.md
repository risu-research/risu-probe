# RISU Probe P6-B29 최종 핸드오프 (2026-11-13)

**결과: B29 독립 소유자 확인 알고리즘과 실제 GitHub 원본 거부 실험 검증 성공. 외부 독립 인간 소유자의 실제 긍정 승인 사례는 아직 없음.** B29 소스와 문서는 별도 연구 브랜치에만 보존. RISU Probe 및 RISU Verify main은 유지.

## 주요 GitHub 기록

- **최종 실제 실행 / 3개 운영체제:** https://github.com/risu-research/risu-probe/actions/runs/43436411185
- **실제 GitHub 원본 승인 및 증거 결합 거부 아티팩트:** https://github.com/risu-research/risu-probe/actions/runs/43436411185/artifacts/14043563167
- **B25 실제 GitHub 사람 승인 및 원본 파일 쓰기:** https://github.com/risu-research/risu-verify/actions/runs/43355918665
- **B28 실제 OpenBao 발급·PostgreSQL 실행·철회:** https://github.com/risu-research/risu-probe/actions/runs/43377450878
- **최종 기술 보고서:** ../../docs/P6B29_INDEPENDENT_OWNER_PROVENANCE_FINAL.md
- **외부 협력자 재현 절차:** EXTERNAL_OWNER_REPRODUCTION_KO.md
- **사전 고정 실험:** PRE_REGISTERED_HUMAN_OWNER_PROVENANCE.md
- **현재 연구 브랜치:** qualification/p6b29-independent-owner-evidence-20261113

## 실제 두 음성 대조군

1. B25의 원본 승인자는 실제 GitHub 계정이었지만, 승인자와 작업 시작자가 같은 계정이었다. 현재 보호 환경에서 Prevent self-review는 꺼져 있고 관리자 우회만 막혀 있다. 따라서 **인간이 승인했다**와 **독립된 두 사람이 승인했다**는 완전히 다른 주장이다. B29는 같은 계정 및 self-review 비활성화를 각각 거부 사유로 기록함.
2. B25 원본 승인 이벤트를 B28 원본 DB 변경의 권한 근거로 결합하려는 경우, B25와 B28의 저장소 ID, 실행 ID, 커밋 해시가 모두 달라 원본 GitHub API에서 즉시 거부됨. 둘 다 개별적으로 성공했던 원본 실행이라도 서로 이어 붙여 특정 행동의 승인이라고 말할 수 없음.

## 실제 구현

- src/risu_mcp_independent_owner_evidence.py
- src/risu_p5d_cli.py에 verify-mcp-independent-owner 새 명령 등록
- pyproject.toml에 패키징 포함
- tests/test_p6b29_independent_owner_evidence.py
- .github/workflows/p6b29-independent-owner-readonly.yml

명령 예:

    risu-probe verify-mcp-independent-owner \
      --repo OWNER/REPO --run-id 123456 \
      --environment protected-environment \
      --effect-repo OWNER/REPO --effect-run-id 123456 \
      --out owner-audit.json

실제 GitHub API를 읽기 전용으로 재조회한다. 원본 승인자 GitHub 숫자 ID, 작업 시작자·재실행자 ID, 저장소 ID, 환경 고정 ID, required reviewer 목록, self review·admin bypass, 브랜치 범위, 원본 run/attempt/commit이 전부 맞아야 플랫폼 수준의 **서로 다른 계정 승인**이라고 할 수 있다. 오래된 승인에 새 실행 효과를 붙일 수 없다.

추가 보강: GitHub 환경 설정 updated_at이 실행 시작 이후라면 사후 설정을 근거로 역사적 보호를 주장하지 못하도록 거부. GitHub 승인 회차가 명확하지 않은 재실행도 거부. 가상 데이터의 구조적 통과는 실제 GitHub 승인 인증으로 기록되지 않도록 별도 분류한다.

## 전체 회귀와 독립 원본

- 원본 GitHub API 음성 대조군 **2/2 기대대로 거부**
- 독립 승인자/실행 이력에 대한 가상 긍정 및 변조 테스트 **30/30 PASS**
- Ubuntu 설치형 RISU 전체 테스트 **592/592 PASS**
- Windows 설치형 RISU 전체 테스트 **592/592 PASS**
- macOS 설치형 RISU 전체 테스트 **592/592 PASS**
- GitHub Actions 모두 읽기 전용 (contents:read/actions:read), 원본 저장소 승인 규칙·리소스·비밀값 변경 없음.

## 이 발견의 의미

RISU Probe가 기존의 내용·원본·실행 효과 증거에 더해 **승인 주체의 독립성**과 **승인한 바로 그 실행인지 여부**를 구분하는 진단 기능을 갖게 됨. 이것은 통상적인 성공 여부 검사가 아니라, 기록이 원래 입증할 수 있는 조건을 넘어 주장하는지 판단하는 좁은 반례 기반 검증이다. GitHub 자체의 새 보안 취약점이나 불법 접근을 발견한 것은 아님.

## 연구 한계

실제로 별개의 인간이 자원 소유자 권한으로 동의하고 직접 자원 결과를 확인한 새 양성 사례는 아직 없음. 두 계정이 서로 다른지도 플랫폼 ID로만 확인 가능하며 실제 자연인 분리나 법적 소유권까지 증명하지 않음. B25 사람 승인과 B28 원본 실행을 하나의 승인 연쇄로 재해석해서는 안 됨. 오프라인의 구조적 테스트를 실제 사람 승인이라고 부르지 않음.

## 다음 단계

진짜 외부 운영자가 자신의 별도 테스트 저장소나 서비스에서 정확한 요청을 받고, 직접 독립 승인을 수행하며, 원본 리소스에 대한 신뢰할 수 있는 권한을 발급·철회해야 함. 협력자에게 자격증명 공유를 요청하지 않고, 지정된 실험 자원에서만 진행. 해당 독립 승인과 원본 효과가 생기면 B29의 원본 GitHub read-only 검증을 실행하고, 별도 자원 감사까지 연결.

사용자가 별도 이메일을 직접 보낼 때까지 RISU는 대리 연락하지 않음.

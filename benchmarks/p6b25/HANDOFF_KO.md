# RISU B25 | 실제 GitHub 사용자 승인과 쓰기 자격증명 격리

기준 2026-11-12 미국 동부시간 / CI 2026-11-13 UTC.
소스 브랜치: qualification/p6b25-real-review-credential-isolation-20261112
소유자 저장소: risu-research/risu-verify, 동일 이름 연구 브랜치.
현재 상태: B25 구현 + 3운영체제 전체 테스트 + 외부 플랫폼 실제 403 통과.
인간의 GitHub Required reviewers 실제 클릭과 그 이후 원격 파일 쓰기는 아직 진행하지 않았음.
양쪽 main 변경 없음.

## 실험 대상
소유자 제안서: benchmarks/p6b25/OWNER_PROPOSED_REQUEST.json
제안서 Git blob: c66e2630c0c4edf15ee467fb758f601de6370ede
제안서는 명시적으로 UNAPPROVED_UNTIL_GITHUB_ENVIRONMENT_REVIEW_EVENT 상태.
실제 대상: benchmarks/p6b25/owner_only_resource.txt
원본 Git blob: c84690efad2ac44fa96605a4d1b7c34efbff52de
원본 SHA256: fe8092741095803fd70cf7c62e516fa752ba296ed8688fc15bb320db5cc64b18
승인 후 의도된 SHA256: 1f3d9970b42d3a8b5ebc163c5678328a6b4aacc9a223f3a7119aa28456717bdb

## 새 제품
RISU 명령: risu-probe enforce-mcp-human-reviewed-write
소스: src/risu_mcp_human_review_broker.py
허가 조건은 GitHub의 실제 특정 workflow run에 대한
GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals 의 승인 기록.
정확히 지정된 환경과 moon10021017 사용자, User 계정, state=approved 확인.
Bot, 잘못된 계정/환경, 미승인, rejected, 재실행 attempt>1 거부.
순수 push 이벤트나 GitHub OIDC 출처서명만으로 인간 동의로 판단하지 않음.

이 코드에는 정확한 소유자 제안서 Git blob을 내장해
다른 파일로 바꾸면 GitHub OIDC signer가 맞아도 거부함.
원본 GitHub 파일의 실제 바이트와 Git blob를 점검 후
원자적인 O_EXCL 일회용 nonce 소비, 정확한 파일 경로에
단 한 번의 GitHub Contents PUT으로 변경.
독립 감사에서 다시 GitHub의 immutable commit과
변경된 딱 한 파일을 검증하도록 준비함.

B24에서는 원본 MCP 프로세스가 저장소 쓰기 토큰을 직접
받았으나 B25에서는 외부 원본 MCP를 쓰기 토큰과 같이
실행하지 않음. 고정된 브로커 Python 코드만 토큰을 갖고
별도 UID nobody 비특권 자식은 빈 환경으로 실행하여
부모 환경 토큰 접근 및 직접 GitHub 쓰기를 거부하도록 설계.
한계: GitHub GITHUB_TOKEN은 여전히 repository-level 쓰기 토큰.
개별 파일 단위 토큰이 아니므로 신뢰된 작성기 또는 runner
자체가 공격자에 의해 변경되면 우회 가능.
이는 신뢰된 한 파일 작성기 코드와 별도 OS UID에 대한
격리 검증이지 신뢰 실행기 자체가 악성이어도 안전한
강제 집행 증명은 아님.

## 완료된 증거
실제 GitHub 읽기 전용 job에서 승인 기록 [] 확인,
원본 B25 파일 unchanged, 직접 GitHub Contents PUT
401/403 거부, 무해한 대상 파일 존재하지 않음 404:
https://github.com/risu-research/risu-verify/actions/runs/43351968519

기존과 신규 모두 포함한 538 tests가
Ubuntu, macOS, Windows 각각 통과:
https://github.com/risu-research/risu-probe/actions/runs/43352914194

Mock approval로 인한 제품 동작 검증은 개발 양성 대조군일 뿐
실제 사람 승인 시험으로 집계하지 않음.
이전 B23/B24의 실제 원본 GitHub MCP 동작 결과는 유지,
B25 자체가 승인 후 실제 원격 변경했다고 아직 주장하지 않음.

## 사용자 GitHub UI에서 필요한 단계
1. https://github.com/risu-research/risu-verify/settings/environments
2. New environment 이름은 정확히 risu-b25-human-owner-approval
3. Required reviewers에 moon10021017 지정.
4. 같은 계정이 trigger하고 직접 승인할 최초 실험이면
   Prevent self-review OFF. 별도 두 번째 검토자를 지정하면
   ON으로 바꿔 독립적인 이인 검증도 가능.
5. Allow administrators to bypass configured protection rules OFF 권장.
6. Deployment branches는 qualification/p6b25-real-review-credential-isolation-20261112 한 개만 허용.
7. GitHub 설정 후 채팅에서 '설정했어'라고 알릴 것.
   그러면 어시스턴트가 해당 연구 브랜치에
   benchmarks/p6b25/REQUEST_HUMAN_REVIEW.txt
   를 최초 생성해 실제 Actions 승인 요청을 시작할 수 있음.
8. 사용자가 GitHub Actions에서 Review deployments →
   Approve and deploy를 직접 눌러 실제 계정의 승인 기록 생성.
9. 승인 완료 후 실제 신뢰 브로커가 파일을 한 번만 수정하고,
   별도 읽기 전용 감사자가 immutable GitHub commit과
   사용자 승인·원본/변경 파일의 byte hash를 독립 검증.

GitHub PAT이나 개인키를 만들거나 보내지 말 것.
기존 GitHub job-scoped GITHUB_TOKEN을 사용함.
현재 실행 승인 전이므로 어떤 파일도 자동 수정하지 않음.
GitHub 기본 브랜치에 변경 없이 연구 브랜치 push trigger로 동작.

설명:
docs/P6B25_REAL_HUMAN_REVIEW_AND_TRUSTED_ONE_FILE_BROKER.md

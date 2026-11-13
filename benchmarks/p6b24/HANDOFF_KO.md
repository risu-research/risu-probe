# RISU Probe P6-B24 인계 | 소유자 승인과 쓰기 자격증명 분리

기준: 2026-11-12 미국 동부 / 실제 GitHub CI 2026-11-13 UTC
RISU 연구 브랜치: qualification/p6b24-no-bypass-owner-broker-20261112
실제 소유자 리포: risu-research/risu-verify
리소스 브랜치: qualification/p6b24-owner-authority-20261112
두 저장소 main은 변경하지 않음.

## 1. 이번에 실증한 본질적 개선

이전 B23은 허가를 확인했지만 에이전트와 실행자가 저장소
쓰기 토큰을 함께 가질 위험이 있었음. B24에서는 실제
GitHub Actions의 각 작업별 토큰을 서로 다른 권한으로 분리함.

실제 작업 3개:
- owner-provenance: contents:read, id-token:write,
  attestations:write. GitHub 실제 관리 계정과 요청 범위를 확인하고
  원본 허가 파일에 GitHub OIDC/Sigstore 증명을 부여.
- untrusted-agent: contents:read. 저장소 쓰기 권한이 아예 없는
  실제 에이전트 작업. GitHub API 직접 PUT과 GitHub 공식 MCP
  원본 create_or_update_file 직접 실행을 모두 시도.
- trusted-broker: contents:write, OIDC 서명 권한 없음.
  별도의 신규 작업에서 owner signed grant와 실제 GitHub
  관리 계정, repo ID, 도구 인자, 원본 Git blob, 신규 내용,
  소프트웨어 공식 배포물 해시, 한 번만 사용하는 nonce를
  재검증한 뒤 정확히 하나의 승인된 원본 MCP 쓰기를 수행.

GitHub는 job별로 다른 installation GITHUB_TOKEN을 발급함.
따라서 untrusted-agent job에서 게이트웨이 소프트웨어를
건너뛰어도 그 환경의 token은 GitHub에서 쓰기 권한이 없음.

## 2. 실제 자원 소유자와 진짜 승인의 출처

조직 risu-research (org ID 316025762)
실제 리포 risu-verify (repo ID 1350184511)
실제 admin 계정 moon10021017
원본 허가 발행 커밋:
f21a899fe5466963b19bfcc8986e10c11776afae

승인 파일:
risu-research/risu-verify,
benchmarks/p6b24/OWNER_AUTHORIZATION.json
허가된 대상:
benchmarks/p6b24/owner_only_resource.txt
허가된 브랜치:
qualification/p6b24-owner-authority-20261112

실제 최초 파일 Git blob:
bd6b674299ba329d871bb05790a85cab3a1f4e5f
실제 최초 파일 SHA256:
80b7fab7d10f7e5be558c42d664135f9e07ad45680f7cb3b3d6a6acbceabfd0f
최종 승인 내용 SHA256:
b792024d10b7d1611b12dd59c4efde3529e84c7dcaffea29c6bfdf3dbf319774

실제 연결된 GitHub 관리 계정의 위임 권한으로 허가 파일을
발행했으며 GitHub가 OIDC/Sigstore로 그 출처를 증명.
외부의 독립적인 자연인이 GitHub 화면에서 직접 승인 버튼을
눌렀다는 사실은 아직 없음. 최초 실제 실행 이벤트는 push.
이 사실을 수동 승인의 증거로 바꾸어 주장하지 않음.

## 3. 게이트웨이를 완전히 우회한 실제 권한 실패

untrusted-agent job의 GITHUB_TOKEN은 contents:read뿐.

A. 실제 GitHub REST API의 파일 생성 PUT 직접 요청
결과 HTTP 403.

B. 공식 github/github-mcp-server v2.1.0 원본 바이너리를
에이전트가 직접 띄우고 실제 create_or_update_file MCP 요청.
결과 isError=true. 내부 실제 GitHub API의 HTTP 403
Resource not accessible by integration.
원본 MCP 7개 JSON-RPC 메시지 증거 보존.

C. GitHub API에서 위의 두 요청 대상 파일 모두 존재하지
않는 것과 소유자 원본 대상 파일이 중간에 변경되지 않은 것 확인.

즉 '우리 RISU가 거부한다'에서 끝나는 실험이 아니라,
에이전트에게 주어진 실제 GitHub 토큰으로 직접 우회해도
플랫폼에서 쓰기 권한 자체가 거부된 실험.

## 4. 독립된 신뢰 실행기만 원본 MCP 쓰기 성공

B24 owner-provenance OIDC 증명을 다시 검증한
trusted-broker job이 별도 contents:write 토큰으로
GitHub 공식 MCP 원본 create_or_update_file을 호출.

공식 원본 패키지:
github/github-mcp-server v2.1.0
Linux 공식 릴리스 SHA256:
a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b

승인된 실제 저장소 변경 커밋:
140b47158ee6e03327e8fb8a98380479d0cd2554
결과 파일 Git blob:
9a4caec165143b9fd6b4c57c09f410aaa36cc141

GitHub 원본 커밋에서 수정한 파일은 위의 승인 파일 딱 1개.
다른 파일 수정 없고, main 수정 없음.
원본 MCP initialize/tools/list/tools/call 실제 통신 증거를
보존했으며 소유자의 서명된 최종 기대 상태 해시와 정확히 일치.

소유자 승인/에이전트 우회/신뢰 실행기 실제 3개 작업:
https://github.com/risu-research/risu-verify/actions/runs/43341365204

## 5. 별도 읽기 전용 감사

제품 코드를 import하지 않는 독립 감사기는 오직
읽기 전용 GitHub 토큰을 사용했음.

GitHub 원본 OIDC/Sigstore 서명 및 owner admin 계정,
관리 조직/리포의 불변 ID, 원본 사전 Git blob,
원본 공식 MCP 전체 7줄 통신, 실제 HTTP403와 MCP error,
승인받지 않은 원격 경로 둘의 부재, 실제 승인 실행 커밋
및 그 커밋에서 바뀐 한 파일을 독립 재확인.

특히 당시 GitHub 원본 워크플로를 해당 커밋의
불변 GitHub 객체로 다시 받아 직접 분석하여
owner-provenance job에 서명 권한,
untrusted-agent job에 읽기 권한,
trusted-broker job에만 쓰기 권한이 선언된 것을 확인.

원본 독립 감사:
https://github.com/risu-research/risu-verify/actions/runs/43342185893
원본 증거 위조 3종류 모두 거부:
https://github.com/risu-research/risu-verify/actions/runs/43342408153

변조 대조군: owner grant 내용 변조,
에이전트 원본 MCP 통신 바이트 변경,
브로커가 주장하는 GitHub 원격 최종 해시 변조.

## 6. 실제 제품 구현

원본 실제 실행 때 소스 고정 커밋:
135c79567f1df99ca68e0f8ad40b58a01123140c

제품:
src/risu_mcp_owner_credential_broker.py
새 설치형 CLI:
risu-probe enforce-mcp-owner-credential-broker

명령 예시:
risu-probe enforce-mcp-owner-credential-broker \
  --grant OWNER_GRANT.json \
  --original-server ./github-mcp-server \
  --original-archive PINNED_OFFICIAL_GITHUB_MCP.tar.gz \
  --authenticating-run OWNER_WORKFLOW_RUN_ID \
  --approval-mode DELEGATED_OWNER_ACCOUNT_GIT_COMMIT_AUTOMATED_DEVELOPMENT \
  --actor OWNER_GITHUB_ADMIN_ACCOUNT \
  --out NEW_RESULT_DIRECTORY

제품은 B24_TRUSTED_BROKER_JOB=yes 환경 설정을 요구하지만
이 환경변수가 비밀번호나 보안 증명인 것은 아님.
진짜 보안 장벽은 GitHub Actions의 분리된 job과
job별 contents:read / contents:write 토큰 접근권.

제품 이식 후 재사용 nonce 거부를 최종 원격 blob 변화로
인한 거부보다 먼저 판별하도록 개선.
실제 GitHub positive 원본 실행은 1회만 수행했으며
제품 테스트 성공을 두 번째 실제 쓰기라고 주장하지 않음.

## 7. 결정적으로 중요한 남은 단계

[독립 자연인 직접 승인]
이번 실제 허가 발행은 사용자가 연결한 GitHub 계정의
위임 API 작업이었음. 독립 인간이 GitHub에서 직접
승인한 기록이 없어 직접 인간 동의라고 주장 불가.

직접 동의 실험은 GitHub 기본 브랜치에 별도의 owner
manual workflow를 설치하고, GitHub Settings >
Environments에서 필수 reviewer를 지정한 다음,
승인권자가 직접 GitHub UI에서 승인하는 과정이 필요.
Prevent self-review도 사용 가능하며 이렇게 하면
승인 요청자와 승인자를 다른 사람으로 분리할 수 있음.
우리 연구 브랜치에서는 사용자의 main을 임의로
수정하거나 본인이 클릭한 척하지 않았음.

[최소권한]
에이전트 job은 실제 contents:read token이라 GitHub가
직접 쓰기를 거부. 그러나 broker job의 contents:write는
repo 전체에 걸리는 GitHub 권한. 특정 한 파일만 수정한다는
것은 브로커의 고정된 소스 정책으로 판정하는 것이므로
신뢰 실행기나 공식 MCP 바이너리가 악의적으로 바뀌면
더 광범위하게 쓸 위험이 있음.
프로덕션급 경계는 브로커 내부의 강제 중재, GitHub App의
특정 repo 접근 제한, 별도 GitHub rulesets/브랜치 보호와
외부 승인자의 신뢰 루트를 추가 검증해야 함.

[신규 외부 취약점]
발견 0개. 원본 공식 GitHub 서버는 읽기 전용 자격증명에서
정상적으로 쓰기를 거부했고, 승인된 브로커에서는
정상적인 한 파일 쓰기를 수행했음. 연구의 실질적인 기여는
이 실제 원본 경계와 독립 재검증.

전체 영문 보고:
docs/P6B24_REAL_OWNER_NO_WRITE_AGENT_BROKER.md

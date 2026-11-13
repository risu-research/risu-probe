# RISU Probe P6-B23 한국어 연구 인계

기준: 2026-11-12 미국 동부 / 실제 CI 기록 2026-11-13 UTC
RISU Probe 연구 브랜치: qualification/p6b23-github-owner-issued-gate-20261112
실제 GitHub 소유자 측 별도 저장소: risu-research/risu-verify
그 소유자 측 연구 브랜치: qualification/p6b23-owner-grants-20261112
두 프로젝트의 main 변경 없음.

## 1. 무엇이 이전 B22보다 개선됐나

B22에서는 서로 다른 Linux UID를 임시로 만든 뒤,
CI가 생성한 자원에 서명한 권한을 실행 전에 집행했음.
B23에서는 실제 GitHub 조직이 관리하는 저장소의 실물 파일을
대상으로 실제 GitHub 관리 권한을 가진 계정이 제한된 승인을
GitHub API로 발행함.

권한 승인 저장소와 RISU 검사기 연구 저장소가 다름.
소유자 측 GitHub Actions가 관리 권한을 GitHub API로
재확인하고, OIDC/Sigstore가 서명한 정확한 허가 문서를
발행함. 원본 MCP 실행 환경에는 OIDC 서명 권한이 없음.
실행 전 GitHub/Sigstore 서명을 검증하고, 정확히 허가받은
저장소 ID, 파일, 브랜치, 원본 Git blob, 변경할 내용,
MCP 도구 이름과 인자, 원본 소프트웨어 SHA를 확인함.

이것은 가짜 로컬 user_id가 아니라 실제 GitHub 조직의
repo_id 1350184511, organization_id 316025762와 실제
admin 권한의 사용자 moon10021017을 GitHub API에서 확인한 결과.

허가를 발급한 실제 관리 계정은 사용자가 연결한 GitHub
앱의 위임된 권한으로 조작되었음. 별도 외부 자연인이
자신의 GUI에서 직접 승인한 실험은 아직 수행하지 않았음.

## 2. 소유자 권한 원본과 서명

실제 GitHub 승인 파일:
risu-research/risu-verify/benchmarks/p6b23/OWNER_AUTHORIZATION.json
연구 브랜치에서의 승인 발행 커밋:
4eab2daf0b705df27658f6159f02165da910bcf1
실제 GitHub 계정 admin 신원 확인, GitHub OIDC/Sigstore 원본
서명 증명, 외부 소스 수신 및 독립 서명 검증 모두 성공.

고정된 실행 전 상태:
file path benchmarks/p6b23/owner_sandbox.txt
pre Git blob de0b72cd177d6f1bb7153a9925bb3a5bf285d521
pre file SHA256:
63edefc58b885353c97883f1ecd6a70c9063c43b8a80d64585977b35a0e098a1

승인된 실행 후 상태:
post SHA256:
185f90a28d7775a1e91341c6a5f25807a9eeff49be86877f9e8468316580de9d
post Git blob:
c4c233d165eb354be7bdbb994fc1f49924b46377

## 3. 공식 GitHub 원본 MCP 서버의 실제 실행

사용한 실제 외부 개발사 소프트웨어:
github/github-mcp-server v2.1.0
공식 Linux 원본 릴리스 tar.gz SHA256:
a442f9db287cea01008bcb55fe6bc0292270301046c3edbd1a8b22d6e4157b2b

원본 stdio MCP initialize, tools/list, tools/call 실제 7개
JSON-RPC 통신을 보존함.
원본 create_or_update_file 도구 1회 호출.
실제 GitHub 원격 저장소에 한 파일이 바뀌는 커밋 생성:
6e7d3e80a3e2bf327a5a1d394010f6cba99c0467

GitHub 서버 API가 실제 커밋에서 파일 딱 한 개가
바뀌었음을 확인. 실물 파일 94바이트에서 112바이트.
로컬 파일만 바뀌었다고 주장하는 방식이 아님.

실제 GitHub 원본 두 작업(소유자 허가 증명+실행):
https://github.com/risu-research/risu-verify/actions/runs/43336892730

실행 전 별도 부정 대조군:
허가 없음, 허가 파일 변조, 다른 경로, 다른 브랜치,
다른 도구 5건 모두 원본 서버 실행 없이 차단.
실행 후 승인 재사용 1건 추가 차단.
이 부정 대조군에는 B22와 같은 독립 strace 기록이
없으므로 OS 차원의 일반적 프로세스 차단 인증으로
과장하지 말 것. 원본 MCP 실제 쓰기는 하나임.

## 4. 독립 읽기 전용 감사

승인 발급 CI와 원본 실행 CI와 독립 감사 CI는 서로 다른 job.
독립 감사는 content write/oidc signer 권한이 없는 환경.
RISU 검사기를 import하지 않는 별도 프로그램이
GitHub 플랫폼에서 원본 파일 Git blob, 원본 결과 커밋,
그 커밋의 변경된 단 하나의 파일, 소유자 admin 계정,
GitHub OIDC/Sigstore, 원본 MCP 통신을 다시 조회해 교차 감사.

이전 감사:
https://github.com/risu-research/risu-verify/actions/runs/43337547529
역사적 불변 커밋 기준으로 고친 재검증:
https://github.com/risu-research/risu-verify/actions/runs/43338759795

소유자 승인 문서·원본 MCP 통신·GitHub 원격 결과 해시
변조 세 종류를 독립 감사에서 각각 거부.

감사는 이후 같은 브랜치에 새로운 승인 작업이 생겨도
이전 결과가 달라지지 않도록 변경 직후의 고정된
실제 Git commit SHA를 통해 파일 상태를 복원하도록 개선됨.
이 감사기 수정은 실제 원본 MCP 실행 이후의 개선이며,
원본 역사적 결과는 절대 변경하지 않았음.

## 5. RISU 실제 제품

벤치마크에서 실제 실행된 출처 고정 코드:
benchmarks/p6b23/run_owner_attested_github_mcp.py
원본 실제 실행 당시 커밋:
2f4a59996b2ba0d7d919072828d19fdc1b0e070f

이를 제품 모듈로 이식:
src/risu_mcp_github_owner.py
새 CLI:
risu-probe enforce-mcp-github-owner

제품은 이후 로컬 nonce 원장 소유권·symlink 검사와
원격 파일의 상태 불일치 때문에 재사용 거부를 혼동하지
않도록 nonce 우선 검사를 강화했음.
이 개선된 제품이 동일한 실제 GitHub 파일을 두 번
수정한 것처럼 주장하지 말 것. 실제 원격 변경은 1회.

기존 기능 및 신규 테스트 490개를 Ubuntu/Windows/macOS
각각에서 모두 통과함.
https://github.com/risu-research/risu-probe/actions/runs/43338260387

## 6. 남아 있는 진짜 독립 외부 인간의 직접 승인

현재 실제 GitHub 관리 계정의 승인 출처를 확보했지만,
사람이 직접 Github에서 yes를 선택한 이벤트는 없음.
원본 성공은 GitHub push 이벤트임.

직접 수동 승인 모드를 연구 브랜치에 추가해,
관리 계정이 직접 승인하면 새로운 GitHub prestate에 대해
짧은 1회성 허가를 발행하고 다시 서명하도록 코드를 준비함.
하지만 이를 실제 수행했다고 주장하지 않음.
GitHub의 workflow_dispatch는 workflow 정의가 기본 브랜치에
설치되어 있어야 수동 실행할 수 있음.
소유자 저장소 main을 임의로 수정하지 않았으므로 이
마지막 대화형 검증에는 별도의 계정 소유자 선택과
검토된 워크플로의 기본 브랜치 설치가 필요함.

아직 GitHub repo 전체 쓰기 토큰을 반드시 게이트웨이만
보유하도록 강제하는 별도 credential broker도 없음.
만약 악성 실행자가 contents:write 토큰을 직접 가질 수
있다면 검사를 우회할 수 있으므로 production-grade
강제집행으로 과장하면 안 됨.
그러나 이 연구에서 지정한 정확한 MCP 호출을 선검증하고
실물 원격 GitHub 데이터의 원본 효과를 독립 검증한
작업 경로 자체는 성공적으로 재현됨.

## 7. 다음 최선 연구

실제 사람이 직접 UI에서 승인한 이벤트(issuer·actor·audience·
resource·scope)를 GitHub OIDC/Sigstore로 증명.
실제 다른 조직의 저장소에서 테스트하면 소유자/검사자
조직까지 분리할 수 있음.
GitHub App 설치권한 또는 최소 권한 credential broker를
사용해 에이전트가 원본 write token을 직접 보유하지
못하도록 한 뒤 실제 허가 전 차단/허가 후 원본 MCP 쓰기
및 독립 GitHub API 감사로 확장.

세부 보고:
docs/P6B23_REAL_GITHUB_ADMIN_ATTESTED_OWNER_PRECALL.md

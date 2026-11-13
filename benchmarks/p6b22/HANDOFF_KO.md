# RISU Probe P6-B22 연구 인계

기준: 2026-11-12 미국 동부시간. 일부 GitHub 검증은 11월 13일 UTC.
연구 브랜치: qualification/p6b22-os-owner-precall-enforcement-20261112
main 미변경. B19–B21 기존 동결 검사기 미변경.

## 1. 이번에 완성한 기능

B21의 사후 권한·효과 대조를, B22에서는 실제 원본 MCP
서버 프로세스 생성 전 집행하도록 확장.

명령: risu-probe enforce-mcp-preflight
제품 코드: src/risu_mcp_preflight.py
동결 핵심 코드 Git blob: 651af884c3303bbe6729a751a89b57d939e9eb6d

인자:
--request, --grant, --trust-root, --trusted-root-sha256,
--revocations, --revocations-sha256, --original-wheel,
--ledger, --server-python, --out

확인 조건:
- 자원 소유자의 실제 Ed25519 사전 서명
- 별도로 고정된 소유자 공개키 SHA256
- 원본 실행자/소유자 POSIX UID 및 리소스 디렉터리 소유권
- 원본 MCP tool 이름·요청 해시·정확한 대상 파일·내용 SHA256
- 실제 실행 소프트웨어의 원본 배포 wheel SHA256
- 승인 당시 파일 상태, 예상 CREATE/REPLACE/NO_CHANGE 방향
- 발급·만료 시점, 중복 nonce 원자적 예약
- 소유자 서명 최신 취소 목록의 별도 고정 해시
- 실제 디렉터리 및 개별 파일 POSIX DAC 쓰기 권한
- 승인할 때만 외부 원본 MCP 프로세스를 시작함

오류·권한 거부 시 원본 도구 호출 0건, exit 3.
승인한 경우 원본 initialize/tools/list/tools/call 실제 통신을
보존하고 실제 파일 효과를 재검사함.

이 제품은 안전한 제한된 write_file 도구에 대한 사전 집행.
모든 MCP 부작용을 차단하는 만능 샌드박스는 아님.

## 2. 독립적인 실제 OS 보안 주체

서명·파일 자원 소유자: www-data UID 33
실제 MCP 원본 서버 실행자: nobody UID 65534
서로 다른 실제 Linux 비특권 사용자임.

소유자는 0700 전용 디렉터리에 0600 Ed25519 개인키를
가지며 실행자는 개인키를 읽을 수 없음.
소유자는 자원 디렉터리를 소유하고 별도로 POSIX ACL을
부여하거나 철회. 실행자는 개인키 없이 자신의 0700 원자적
재사용 방지 원장으로 허용된 MCP 원본 요청만 수행.
소유자가 각 요청의 실행 전 서명 허가를 발급하고,
실행 전후 대상 파일 내용도 각각 자신의 개인키로 서명함.

중요: 이 두 UID는 실제 독립된 운영체제 사용자 계정이지만
독립적인 외부 자연인 두 사람이 아님. CI 관리자는 sudo 권한을
가지므로 두 주체를 관리할 수 있고, 외부 사람이 직접 실제
자기 자산에 대한 동의 절차를 수행한 실험은 아님.

## 3. 사용한 외부 원본

개발 조직: kujirahand/mcp_server-filesystem
고정 Git commit: 1aff1e094ed317ec2c5de06591978781d660c48a
PyPI 원본: filesystem-mcp 1.0.2
wheel SHA256:
94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235
원본 server.py SHA256:
c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8

실행 모듈, PyPI wheel, 원래 GitHub 공개 소스 바이트 일치.
업스트림 공식 암호학적 서명 발행이라고 주장하지 않음.

## 4. 실제 외부 MCP 원본 실행 결과

승인 3건, 원본 MCP 프로세스 생성 및 실제 성공:
allowed_create: 파일 새로 생성, 42바이트
allowed_noop: 기존 동일 내용 덮어쓰기, 무변화
allowed_replace: 소유자 서명 + 실제 ACL 승인,
64바이트 기존 파일을 42바이트로 교체

실행 전에 거부한 7건:
denied_replay: 이미 사용한 서명 허가 재사용
denied_no_grant: 허가 발급 자체 없음
denied_signed_scope: 허가는 NO_CHANGE인데 요청은 CREATE
denied_revoked: 소유자의 새 서명 취소 목록에 포함
denied_os_dac: 별도 POSIX ACL을 소유자가 철회
denied_stale_state: 승인 후 소유자가 파일 내용 변경
denied_tampered_request: 서명 뒤 원본 요청 내용 바꿔치기

Linux strace -f -e execve 기록으로 실제 원본 서버의 시작 여부
독립 확인. 승인 3/3건에만 원본 프로세스 실행.
거부 7/7건 서버 프로세스 시작 0건, 대상 파일 변경 0건.
각 실험의 전후 관측도 자원 소유자 UID 33이 직접 서명해 보존.

첫 실제 CI:
https://github.com/risu-research/risu-probe/actions/runs/43332919600

## 5. 독립 검증·재실행

완전히 새 GitHub Ubuntu 호스트에서 새 owner Ed25519 키와
새 임시 파일을 이용, 동일한 실제 외부 서버를 다시 설치.
10개 실제 시험 모두 같은 승인/차단 판정 반복 성공.
두 CI의 공개키 지문은 서로 다름.

RISU B20/B21/B22 판정 코드를 import하지 않는 독립 감사기:
benchmarks/p6b22/independent_os_owner_preflight_audit.py

외부 원본 wheel, 원본 MCP stdio, 시스템 execve, 사전 서명,
별도 서명 취소 목록, 20개씩의 소유자 서명 물리적 파일 관측과
실제 파일 바이트를 독립 재검증.
서명 관측 변조·실제 파일 변조·가짜 OS 시스템 호출은 모두 거부.

두 환경 합산:
실제 원본 MCP 6건, 실행 전 차단 14건,
실제 OS 소유자가 서명한 실행 전후 관측 40건.
신규 외부 upstream 취약점 발견 0건.

두 번째 CI:
https://github.com/risu-research/risu-probe/actions/runs/43333559961

## 6. 전체 회귀와 사전 고정 연구의 정직한 기록

기존 모든 기능 포함 471개 테스트를 Ubuntu, Windows, macOS
각각에서 전부 통과.
https://github.com/risu-research/risu-probe/actions/runs/43332643910

초기 진짜 개발 실행에서 서명된 REPLACE 승인만으로는
OS의 파일별 쓰기 권한을 넘을 수 없어 외부 원본 작업이
실패하는 것을 발견. 집행기에도 개별 파일 DAC 사전 점검을
추가하고 소유자가 실제 ACL을 승인하도록 개선.
이 코드는 원래 동결 뒤 개발 관측에 따른 개선이었음을 기록.
원본/수정 동결 설계 파일 모두 보존:
benchmarks/p6b22/FROZEN_PRECALL_OS_OWNER_EVALUATION.json
benchmarks/p6b22/FROZEN_PRECALL_OS_OWNER_EVALUATION_V2.json

독립 감사에서 setgid bit를 포함한 02700 디렉터리를
0700과 비교해 실패한 것도 실제 소유자/그룹/기타 권한
비트로 수정. 원본 실행 증거와 판정 대상은 바꾸지 않음.

## 7. 다음 연구로 남긴 검증 경계

현재 달성한 것은 독립 POSIX UID/비밀키/실제 OS 권한을
결합한 좁은 MCP 요청의 사전 집행 실험임.

실제 외부 사람이나 독립 기관이 자신의 신원으로 자기
리소스에 대해 직접 동의·서명한 것은 아직 수행하지 못했음.
이 주장은 별도 독립 소유자 참여, 신뢰 루트 등록, 동의 증명,
원격 OAuth issuer/audience/scopes 검증을 해야 가능.

또한 모든 숨은 서버 부작용에 대한 샌드박스, 경쟁 상태
제거, 생산환경용 분산 nonce/취소 원장이 완성된 것은 아님.

상세 보고서: docs/P6B22_REAL_OS_OWNER_PRECALL_ENFORCEMENT.md

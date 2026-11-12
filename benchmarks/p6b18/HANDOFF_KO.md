# RISU Probe P6-B18 실행 바이너리 출처 검증 핸드오프

날짜: 2026-11-12
브랜치: qualification/p6b18-executed-binary-provenance-20261112
상태: 독립 원본 빌드, Sigstore 증명, 실제 프로세스 실행, 독립 재실행, 합성 반례 검증 완료
기존 main 및 B15-B17 검사기: 변경 없음

## 1. 정확한 연구 목적
B17은 실행 당시 MCP tools/list의 계약이 외부 Git 저장소의 특정
커밋/파일에 선언된 계약과 일치하는지 검증했다.

B18은 그 소스에서 실제로 빌드한 바이너리, 서명된 빌드 대상,
실행 중인 Linux 프로세스 이미지, 원본 MCP 통신을 직접 연결한다.

## 2. 구현
제품 명령: risu-probe verify-mcp-runtime
핵심 코드: src/risu_mcp_runtime_origin.py
실제 프로세스 캡처: benchmarks/p6b18/capture_actual_go_process.py
독립 감사: benchmarks/p6b18/independent_source_runtime_audit.py
합성 반례: benchmarks/p6b18/negative_runtime_evidence_controls.py
전체 회귀: tests/test_p6b18_runtime_origin.py

연구 규칙 사전고정:
benchmarks/p6b18/FROZEN_SOURCE_BUILD_RUNTIME.json
Git 원본 소스 핀:
benchmarks/p6b18/SOURCE_GIT_OBJECT_MANIFEST.json

검증기 자체는 네트워크에 연결하거나 외부 바이너리를 실행하지 않는다.
사용자가 제출한 증거의 일관성을 확인하며, 실제 Sigstore 암호학적
서명 검증은 별도 GitHub CI의 gh attestation verify에서 수행한다.

## 3. 새 원본 외부 서버
조직: modelcontextprotocol/go-sdk
커밋: 328036ea2090c83f28c41a42ee4c9e5ec7393a4f
서버: examples/server/toolschemas/main.go
블롭: 0a2cfbd214798cd094fbe63162e78e7cc5bcab33
go.mod: 3287a95780c8160bdbb4554fb2f509ca369197a4
go.sum: c13454aad50d66edfca523be20fd9c230ff100c7

빌드: Go 1.25.0, linux/amd64, CGO_ENABLED=0,
go build -trimpath -buildvcs=false -mod=readonly '-ldflags=-buildid='
서로 다른 CI runner A/B에서 독립 컴파일 결과의 바이트와 SHA-256이 일치.

원본 빌드 바이너리 SHA-256:
c11061e35013c28f273e92ed44ff8f76eb21f8d547a76c93c7b2840c8cc5ef8f

GitHub Actions에서 actions/attest@v4로 빌드 증명을 생성했고,
Sigstore public-good 인증서 및 Rekor 기록이 남았다.
GitHub CLI gh attestation verify는 사전에 지정한 워크플로 서명자와
해당 바이너리 SHA-256을 독립 검증했다.

**서명 주체는 RISU의 GitHub Actions다. 외부 modelcontextprotocol
개발조직이 공식 배포 실행파일을 직접 서명했다는 뜻은 아니다.**
GitHub 서명 증명에 외부 Git 커밋이 자동 재료로 포함된 것도 아니며,
별도로 고정된 GitHub 원격 트리와 CI 원본 소스/빌드 기록을 대조한다.

## 4. 실제 실행 증거
서명된 바이너리 A를 직접 실행, PID 2538.
실행 전/후 /proc/PID/exe 해시 모두 위 바이너리와 일치.
procfs inode, cmdline, 디스크 파일 해시도 동일성 확인.
정확한 원본 MCP stdio와 다음 네 호출을 기록:
1. simple greeting / name RISU => Hi RISU
2. manual greeting / name B18 => Hi B18
3. manual greeting / name NAME_TOO_LONG_FOR_ORIGINAL_TOOL => isError:true
4. unvalidated greeting / user B18 => Hi B18

별도 GitHub Actions에서 동일한 빌더 B의 원본 바이너리로 새로운 PID
2565에서 위 네 호출을 다시 실행. 이전과 응답 내용이 모두 동일했고
새 프로세스에서도 /proc/PID/exe 실행 전후 SHA-256 일치.

원본 두 번 실행 = 8개 호출. 신규 외부 결함 확정 = 0개.

## 5. 검증 CI
첫 원본 빌드·Sigstore·실행:
https://github.com/risu-research/risu-probe/actions/runs/43304077747

별도 재실행·독립 감사·변조 대조군:
https://github.com/risu-research/risu-probe/actions/runs/43305633121

설치형 전체 RISU 회귀:
https://github.com/risu-research/risu-probe/actions/runs/43304723059

Ubuntu/Windows/macOS에서 각 331개 테스트 모두 통과.
새 제품 코어 테스트에는 정상 및 변조·불완전 증거 대조군 21개 포함.

별도 감사의 16개 합성 변조 사례는 모두 거부:
바이너리 변경, Git 원본 파일 변경, 잘못된 git SHA,
빌더 불일치, Go 버전 불일치, 잘못된 서명 대상/서명자,
실행 파일 변경, inode 교체, MCP stdio 변조 등.
이들은 의도적으로 만든 합성 케이스이며 실제 외부 결함이 아니다.

## 6. B17 대비 의미
B17: '이 세션의 계약이 외부 원본 파일과 일치한다.'
B18: '외부 원본에서 빌드한 바이너리의 SHA가 서명 검증된 대상 및
실제로 실행 중이던 프로세스 이미지와 일치한다.'

B18 원본 서버는 Go에서 스키마를 동적으로 생성하므로 B17 Python
정적 AST의 계약 출처 검증과 동일한 커버리지를 가진다고 주장하지
않는다. B18은 실행 바이너리 출처를 독립 평가한 별개 증거 계층이다.

## 7. 한계와 주의
- 실행 당시 원본은 실제 프로세스에서 측정했지만 오프라인 JSON 증거만
  다른 곳에서 읽는다고 프로세스 신원이 암호학적으로 인증되지는 않는다.
- GitHub CI와 서명 검증 환경에 대한 신뢰가 필요하다.
- 서명자는 RISU 자가 검증 빌드, 업스트림 서명된 공식 릴리스 아님.
- 바이너리 출처가 확인되어도 기능적 정확성이나 모든 결함 부재를 의미하지 않는다.
- Linux /proc 실측을 했고, 다른 운영체제에서는 오프라인 검사기 테스트만 수행했다.
- 외부 조직 소스를 사전에 보고 선택했으므로 블라인드 결함 탐지 연구 아님.
- 신규 외부 결함 0건, 일반적인 탐지율이나 정밀도 추정 불가.

## 8. 다음 B19 제안
공식 개발조직의 서명된 릴리스 및 독립 SBOM/빌드 출처를 실제 실행
바이너리와 연결하는 새로운 코호트를 확보하자. 기존에 손대지 않은
진짜 외부 수정 전후 결함을 사전에 고정하고, 정상 대조군도 포함해
RISU의 결함 탐지 능력을 검증하는 것이 다음 연구급 도약이다.

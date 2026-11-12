# RISU Probe P6-B19 독립 서명 배포물의 실제 수정 전후 결함 검증 핸드오프

작성: 2026-11-12
GitHub 연구 브랜치:
qualification/p6b19-upstream-signed-wheel-real-repair-20261112
기존 main, B15-B18 연구 브랜치: 변경하지 않음

## 1. 핵심 성과
실제 외부 개발 조직 modelcontextprotocol/servers가 자체 GitHub Actions
Trusted Publisher 워크플로로 발행·서명한 공식 PyPI 배포물 두 버전을 확보했다.

결함판: mcp-server-git 2026.11.4
수정판: mcp-server-git 2026.11.11
공개된 보안 권고: GHSA-6hqx-gqrx-c5r2, 2026-11-11 공개
재현된 문제: 읽기 전용 git_status 호출이 저장소 로컬 Git 설정
core.fsmonitor가 지정한 프로그램을 실행할 수 있었음.

이번 결과는 공개된 결함의 독립 재현이며 신규 취약점 발견이 아니다.

### 진짜 중요한 발견
네 실험의 실제 MCP git_status 응답 JSON 내용이 완전히 같았다.
원본 결과 본문 SHA-256:
427e379e413fcb703d516e1458ab2e6acc851e561027fba4ab21cf100717b60b

그런데 외부 실행 부작용은 결함판 + 위험 설정에서만 실제로 발생했다.
따라서 MCP 응답만 수집해 비교하는 검사로는 해당 결함을 알 수 없고
독립적인 실제 외부 상태/실행 효과 관측이 필요하다는 구체적 증거가 되었다.

## 2. 검증된 공식 원본 아티팩트

[결함판 2026.11.4]
공식 PyPI wheel:
mcp_server_git-2026.11.4-py3-none-any.whl
SHA-256: 0cdaa8f446554d020f8ffa0e44ef45b89df4ed4deaeb961b4305d8a2852b4e0e
서명 인증서의 원본 Git commit:
36380287ed3b15d115b55f546617d723072b1296
server.py Git blob:
ca69538746a24f70e3e1c8602d5fcd2d1bb933f0
실제 소스 SHA256:
2304871e38ddd95ed807f628cc68b0e0cdd8ec2e82401110211ea8ea647715a5

[수정판 2026.11.11]
공식 wheel:
mcp_server_git-2026.11.11-py3-none-any.whl
SHA-256: 2197a56393bba71f152c6dae55a4ad9107987b9fb9c596b87bbb85a4e0dacf90
서명 인증서의 원본 Git commit:
e1dc4b18dbb948921da37f3d4224a628730b43b0
server.py Git blob:
cd1d874ece4e44ea95b23d9dd933a0a74176187f
실제 소스 SHA256:
64cca3830b52f935dc254f13cca0ad4a8c0d0b024b0c6d0ec1f327966aa3ace2

서명은 RISU가 새로 발행한 것이 아니라 실제 외부 개발 조직의 PyPI
Trusted Publishing 서명이다. pypi-attestations==0.0.31로 두 wheel
모두 실제 암호학적 검증 성공.
별도 실행 환경에서 둘 다 한 번 더 서명 검증 성공.
X.509 Sigstore 소스 Git commit 및 워크플로 확인.
실제 설치된 Python server.py 바이트 = 원본 wheel 바이트 =
원본 개발조직 Git 커밋의 해당 server.py 바이트.

중요한 표현 구분: 이는 PEP740 PyPI Publish Attestation이며, 모든 빌드
재료를 인증하는 완전한 SLSA 재현 빌드 증명은 아니다.
실제 원본 실행 증거도 CI 환경에서 수집된 것이며,
단독 JSON 기록만으로 악의적 런타임 프로세스를 원격 증명한 것은 아니다.

## 3. 사전 동결 연구 설계
- 버전, 공식 배포 wheel SHA, 원본 Git 커밋, 대상 도구, 입력 4개를
  실행 전에 고정했다.
- 검사기 동결: src/risu_mcp_signed_repair.py
  Git blob: 41bb9439174c37a53481db3e025cb9601ae6040f
- 동결 문서: benchmarks/p6b19/FROZEN_PUBLISHER_WHEELS_REAL_GIT_REPAIR.json
  benchmarks/p6b19/FROZEN_DETECTOR_BEFORE_NATIVE_EVAL.json
- 코드가 실행 중인 결과에 맞게 수정되지 않았다.
- 초기 CI 2건은 각각 의존성 비교의 wheel 설치 경로 및 검사 입력 폴더
  조립 오류로 실패했다. 원본 연구 사례/판정 규칙은 변경하지 않았고
  연구 보존 기록에서 해당 시도도 확인할 수 있다.

## 4. 원본 실행 결과
매번 새로운 임시 Git 저장소와 격리 가상환경을 사용했다.
읽기 전용 MCP git_status 호출만 수행했다.
외부 코드 대신 안전한 스크립트가 같은 임시 루트 아래에
고정된 marker 문자열만 기록하도록 했다. 기밀 데이터/네트워크 없음.

버전        위험 설정    MCP 정상 응답   외부 프로그램 실행
2026.11.4  있음         성공             1회
2026.11.4  없음         성공             0회
2026.11.11 있음         성공             0회
2026.11.11 없음         성공             0회

모든 응답의 본문이 동일하다는 것을 SHA256으로 독립 확인했다.
네 실험 모두 MCP initialize 및 tools/list 원본 응답을 확보하고
서버가 광고한 git_status 도구와 정확한 tools/call을 대응시켰다.

첫 성공적인 공식 원본 및 RISU 판정:
https://github.com/risu-research/risu-probe/actions/runs/43316866530

별도 runner에서 공식 서명 재확인, 두 버전 새 프로세스 재실행,
두 번째 실제 호출 4건까지 모두 동일 결과:
https://github.com/risu-research/risu-probe/actions/runs/43317961883

전체 실제 원본 MCP 호출 8건. 새로 발견된 외부 취약점 0건.
이미 알려진 진짜 취약점의 수정 전후 재현 성공 1건.

## 5. 독립 감사
RISU 제품 코드를 사용하지 않는 별도 감사기:
benchmarks/p6b19/independent_publisher_hidden_effect_audit.py

확인 내용:
- wheel 파일 원본 SHA256과 PyPI 발행 서명 확인
- X509 서명 인증서 SAN, Git commit 확장 OID 확인
- 실제 공개 Git server.py 파일과 wheel 및 설치된 코드의 동일성
- 두 버전 설치 의존 패키지의 동일성
- 정확한 4개 원본 MCP 요청/응답 원시 바이트 및 서버 버전 확인
- 응답 JSON 본문 4개의 정규화 SHA256 동일성 확인
- 정상 대조군 2개와 위험 설정 부작용의 차이를 별도 판정
- 서명된 wheel 변조와 외부 marker 증거 위조를 거부

원본 소스를 실행하지 않는 오프라인 제품 비교기는
RISU CLI의 compare-signed-mcp-repair이며, 자체적으로
PyPI 서명을 암호학적으로 검증하지는 않는다.
서명 검증은 별도 CI에서 실제 공식 툴로 수행한다.

## 6. 전체 회귀 테스트
B19 신규 합성 대조군 18개 포함, 기존 전체 RISU 패키지
Ubuntu, Windows, macOS 운영체제별 349개 테스트 각각 통과.
https://github.com/risu-research/risu-probe/actions/runs/43315902509

## 7. 앞으로의 연구 판단
이번에 증명된 것은 '서명된 외부 공식 배포가 있다고 좋은 서버라는 뜻은
아니며, 실제 실행 부작용은 MCP 응답으로 드러나지 않을 수 있다'는
관측 가능한 반례다. 이 결함은 외부 보안 권고로 사전 공개됐으므로
세계 최초 발견이나 새로운 취약점이라고 주장하면 안 된다.

본 사례는 향후 RISU의 진짜 blind 평가 이전에 사용되는 개발
positive control로 전환한다. 다음 단계는 이 실제 증거 구조를
특정 git_status나 해당 버전에 하드코딩하지 않는 재사용 가능
효과 판정 엔진으로 일반화하고, 처음 보는 별도 개발 조직의 서명된
원본 버전/수정본과 정상 대조군에 평가 규칙을 사전 고정하는 것이다.

## 8. 재현 링크
세부 문서: docs/P6B19_PUBLISHER_SIGNED_HIDDEN_EFFECT_REPAIR.md
원본/정상 결과: .b19-native-firstpass/<VERSION>/<CASE>/
공식 배포 서명/소스: .b19-official/<VERSION>/
정량 결과: .b19-final/REAL_BEFORE_AFTER_FIRSTPASS.json
독립 감사 기록: .b19-review/INDEPENDENT_FIRSTPASS_AUDIT.json
                 .b19-review/INDEPENDENT_SECOND_PROCESS_AUDIT.json
연구 GitHub 브랜치:
https://github.com/risu-research/risu-probe/tree/qualification/p6b19-upstream-signed-wheel-real-repair-20261112

참고: PyPI 서명은 공개 원본 파일의 출처를 인증한다.
실제 서버 프로세스의 실행 효과 증거는 같은 CI 내의 격리 환경에서
관측해 남긴 것으로, 완전한 원격 프로세스 증명으로 부르지 않는다.

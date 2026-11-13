# RISU Probe P6-B32 최종 핸드오프 | 2026-11-13

**상태: 개발·원본 외부 평가 성공, 실제 main 승격 완료. 외부 협력자 불필요.**

## 핵심 성과

기존 B31 검증기는 개발·배포 저장소와 서명 워크플로의 저장소가 같다는 가정이 있었다. B32에서는 GitHub Actions 원본 서명 인증서의 출처와 서명 주체를 분리하고, **정확히 신뢰하겠다고 지정한 별도 서명 워크플로**만 허용하는 검증 명령을 구현했다.

- 원본 제작자 저장소: UpCloudLtd/upcloud-cli
- 원본 서명 저장소: UpCloudLtd/workflows
- 실제 서명 인증서: https://github.com/UpCloudLtd/workflows/.github/workflows/build-provenance.yaml@refs/heads/main
- 실제 소스 Git ref: refs/tags/v3.37.0
- 최초 평가 실행: https://github.com/risu-research/risu-probe/actions/runs/43450828852
- 최종 제품 코드·공격적 대조군·Linux/Windows/macOS 테스트: https://github.com/risu-research/risu-probe/actions/runs/43452832725
- 보고서: ../../docs/P6B32_ORIGINAL_SIGNED_DELEGATION_FINAL.md

### 실증된 명확한 문제 2건

1. 정당한 별도 워크플로 서명이 기존 B31의 동일 저장소 제한 때문에 거절될 수 있다. B32는 신뢰할 서명자의 정확한 인증서 SAN을 지정한 뒤 원본 GitHub/Sigstore 암호학 검증을 호출한다. `--allow-delegated`를 명시해야 한다.
2. 정당한 원본 `txn2/kubefwd`의 서명 대상 이름은 `./kubefwd_Linux_x86_64.tar.gz`였다. 릴리스 파일 이름과 바이트 해시는 일치한다. B32는 단일 `./` 별칭을 허용하되 임의의 경로·`../` 등을 허용하지 않는다.

### 공식 CLI의 제약까지 실제 확인

`gh attestation verify`는 `--signer-repo`와 `--cert-identity`를 동시에 받을 수 없다. 초기 통합 실패의 실제 원인이었다. B32는 둘을 동시에 넘기지 않고, 원래 저장소·워크플로 경로·서명자 ref가 모두 들어 있는 정확한 `--cert-identity`로 검증한다. 소스 저장소·소스 ref도 별도 조건으로 체크한다.

## 사전 고정 6개 외부 원본

| 사례 | 원본 배포물 | 결과 |
|---|---|---|
| H1 | mitre/hdf-libs v3.5.1 | GitHub 공개 attestation API 404, **UNVERIFIED** |
| H2 | txn2/kubefwd v1.25.17 | **VERIFIED**, 정확한 바이트·`./` 별칭 |
| H3 | UpCloudLtd/upcloud-cli v3.37.0 | **VERIFIED**, 별도 UpCloudLtd/workflows 서명 |
| H4 | axonops/audit v0.2.5 | **VERIFIED**, 실제 signer source는 refs/heads/main |
| H5 | klodr/gmail-mcp v3.0.0 index.js | **VERIFIED**, 코드를 고정한 뒤 처음 본 새 배포자 |
| H6 | libredb/libredb-studio 1.3.0 CycloneDX SBOM | **VERIFIED**, 코드를 고정한 뒤 처음 본 새 배포자 |

H1~H4는 원본 비교와 규칙 개발에 사용. H5와 H6은 **B32 코드 SHA `a3ab9b0faaa377a2d2ce3fba4e4ee7d2c92caea0`를 먼저 고정하고** 별도 계획서를 기록한 뒤 실제 암호학 결과를 조회한 보류 평가셋이다. 두 건 모두 고정된 검증 규칙 변경 없이 원래 서명과 RISU 검증이 성공했다.

- 최초 계획: LOCKED_ORIGINAL_PUBLISHER_HOLDOUT.md
- 진짜 별도 미사용 개발조직 평가셋 계획: SEALED_NEVER_SEEN_PUBLISHER_HOLDOUT_H5_H6.md
- 고정 H5/H6 독립 평가 실제 실행: https://github.com/risu-research/risu-probe/actions/runs/43453821659

배포물 6건에 대한 최종 결과는 **5건 서명 검증 성공, 1건 원본 증명 조회 불가**다. H1을 다른 사례로 바꿔 성공률을 부풀리지 않았다.

## 공격적 대조군

원본 실행에서 실제 바이트 1비트를 변조하고 새로운 SHA-256을 공격자 측에서 계산해 넘겨도 GitHub 원본 암호학 검증이 실패했다. 다른 개발조직의 서명자를 붙이거나, 명시적 위임 허용을 생략하거나, 원본 검증 기록의 certificate source repository/ref/SAN, signed subject filename/해시, SLSA 생산자 워크플로를 조작하면 모두 거부했다.

**암호학 검증은 GitHub 공식 CLI/Sigstore 신뢰 루트가 수행한다.** 원본 JSON 파일을 조작한 단위 테스트는 정책 파서의 정확성을 평가하는 것으로서 새로운 서명 검증을 의미하지 않는다.

한 개의 유효한 서명은 그 개발조직의 빌드 출처를 뒷받침할 뿐, B25 GitHub 파일이나 B28 PostgreSQL 데이터를 바꾸는 다른 소유자의 승인 근거가 되지 않는다. 출력의 소유자 승인 및 실제 자원 변경 속성은 계속 `UNVERIFIED`로 남긴다.

## 실제 RISU Probe main 병합

요청에 따라 연구 브랜치를 통째로 합치지 않고 **기존 안정판 main에서 분기한 통합 브랜치**에 독립 검증기만 선별 이식했다.

- PR #2: https://github.com/risu-research/risu-probe/pull/2
- 병합 커밋: `a1b4afdb7a4d8ee3a9f4c543924b6428aba7e137`
- 새 preview 버전: **0.9.22.dev0**
- 안정판 사용법: https://github.com/risu-research/risu-probe/blob/main/docs/DELEGATED_SIGNED_PROVENANCE.md
- 설치 명령 추가: `risu-probe verify-delegated-signed-provenance`
- 이전 B31 명령 유지: `risu-probe verify-signed-release-provenance`
- 변경 파일 6개: `src/risu_delegated_signer.py`, `src/risu_p5d_cli.py`, `pyproject.toml`, `tests/test_p6b32_original_delegated_signer.py`, `docs/DELEGATED_SIGNED_PROVENANCE.md`, `.github/workflows/b32-delegated-signed-source-product.yml`.
- main 병합 전 PR 검증: https://github.com/risu-research/risu-probe/actions/runs/43454766698 (4작업 성공).
- 병합 후 main CI: https://github.com/risu-research/risu-probe/actions/runs/43455008883

Windows·macOS·Ubuntu에 설치한 실제 wheel에서 각각 **81/81 테스트 성공**. 별도 Linux CI에서 5개 서로 독립된 원본 GitHub 릴리스의 Sigstore 서명을 직접 검증.

## 정확한 연구적 평가

이번 B32는 기존 GitHub CLI의 `--cert-identity` 및 in-toto/SLSA가 이미 지원하는 서명자·소스 증거를 RISU 제품에 실제로 연결한 것이며, 새로운 암호학이나 in-toto보다 본질적으로 우수한 검증 기술을 발명했다고 주장할 근거는 없다. **실제 별도 원본 소프트웨어 개발조직 2개의 사전 고정 홀드아웃**에서 검증했지만 샘플이 작아 통계적으로 일반적인 오탐률을 주장하기 어렵다.

다음 비인간 협력 연구 주제는 유효한 서명이 존재하는 복수 증거 사이에서 **동일한 특정 소유자의 승인·실행·실제 자원 변경이 인과·시간·객체별로 연결되는지** 독립된 신규 원본 사례로 검증하는 것이다. 외부 사람 협력은 계속 후순위.

이메일·외부 메시지는 보내지 않았고, RISU Verify의 main은 변경하지 않았다.

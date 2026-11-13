# RISU Probe P6-B27 최종 연구 핸드오프

**상태: 서로 다른 개발 조직의 원본 자원 서비스 2종에 대한 실제 권한 집행과 독립 감사 성공.**

- GitHub 브랜치: `qualification/p6b27-external-resource-enforcement-20261112`
- 보고서: [P6B27_TWO_ORIGINAL_RESOURCE_BACKENDS_FINAL.md](../../docs/P6B27_TWO_ORIGINAL_RESOURCE_BACKENDS_FINAL.md)
- B26 기존 성공 대조군은 보존, 이번 연구는 독립 업스트림 PostgreSQL + SeaweedFS 원본 구현 사용
- RISU Probe 및 RISU Verify의 `main` 변경 없음

## 원본 GitHub 실행 및 아티팩트

| 대상 | 독립 GitHub 원본 실행 | GitHub 보관 아티팩트 |
|---|---|---|
| PostgreSQL 원본 서버, 권한 발급, 원격 상태 실측 | [#43363316209](https://github.com/risu-research/risu-probe/actions/runs/43363316209) | [14009520787](https://github.com/risu-research/risu-probe/actions/runs/43363316209/artifacts/14009520787) |
| SeaweedFS 4.53 원본 바이너리, 분리된 Linux 사용자 S3 호출 | [#43365564417](https://github.com/risu-research/risu-probe/actions/runs/43365564417) | [14010580338](https://github.com/risu-research/risu-probe/actions/runs/43365564417/artifacts/14010580338) |
| 원본 두 아티팩트의 공통 권한 효과 판정 | [#43365668801](https://github.com/risu-research/risu-probe/actions/runs/43365668801) | [14009802925](https://github.com/risu-research/risu-probe/actions/runs/43365668801/artifacts/14009802925) |

## 최종 실측

PostgreSQL 18.6: 합법적으로 허용된 정확한 행의 상태 변경 1회 성공, 미허가 접근 15개 모두 거부 또는 원본 행 0건 영향. 동시에 들어온 두 정상 변경 중 한 번만 반영 [0,1]. 데이터베이스 재시작 후 재사용 시도 0건 반영. 소유자 SQL 권한 REVOKE 이후 쓰기 거부. 원본 PostgreSQL 시스템 카탈로그와 실제 저장된 행을 따로 조회한 독립 감사 PASS.

SeaweedFS 4.53: 개발자의 공식 GitHub 릴리스 `linux_amd64.tar.gz` sha256 `d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d`을 확인한 후 원본 바이너리 그대로 실행. 공식 `-s3.iam.readOnly=false` 옵션으로 네이티브 IAM 발급 허용. 한 객체 ARN에만 `PutObject` 가능한 액세스 키를 발급. 정확한 객체 HTTP 200, 비슷한 경로와 다른 객체 HTTP 403, 버킷 목록 403. **허용된 객체에 다른 내용 쓰기 HTTP 200 및 반복 쓰기 HTTP 200**. 원래 소유자가 자격증명 Inactive 처리한 뒤 HTTP 403. 독립 감사가 원본 S3 GET 바이트와 IAM 정책을 확인해 PASS, 조작된 결과 거부.

권한 분리 보강: SeaweedFS의 직접 S3 요청 8건을 모두 별도 Linux UID 65534 자식 프로세스가 실행. 이 프로세스는 원본 서버와 신뢰 권한 발급자의 `/proc/.../environ` 읽기를 거부당했고, 소유자 관리자 자격증명을 전달받지 않았음. 루트인 CI 실험 관리자는 신뢰 대상에 포함됨.

## 공통 권한 성질 (원본 효과의 독립 감사 기준)

| 성질 | PostgreSQL RLS(본 연구에서 발급한 정책) | SeaweedFS S3 IAM(본 연구에서 발급한 정책) |
|---|---|---|
| 정확한 객체/행 범위 | 검증 성공 | 검증 성공 |
| 변경 후 내용 지정 | 검증 성공 | 검증 불가, 다른 바이트 허용 |
| 변경 전 상태와 상태 전이 조건 | 검증 성공 | 이 정책에서 지원 안 됨 |
| 동일 허가에 따른 효과 반복 방지 | 검증 성공(기존 상태 조건) | 검증 불가, 반복 PUT 허용 |
| 권한 발급자의 철회 | 검증 성공 | 검증 성공 |
| 실제 결과의 독립 확인 | 검증 성공 | 검증 성공 |

## 성과의 올바른 해석

외부 백엔드 2종에 적용해 객체 범위·내용·전이 방향·반복·권한 철회라는 서로 독립된 성질을 판단할 수 있었음. 이 관찰은 RISU의 **claim-specific authority verification**에 실증적 근거를 더한다.

중요: PostgreSQL의 원본 RLS 시스템과 SeaweedFS의 원본 S3 IAM은 본래 권한 모델이 다름. PostgreSQL에는 우리가 직접 만든 기존 상태/변경 후 값 제약이 있고, S3 정책에는 객체 PUT 권한만 담김. S3가 다른 바이트나 재사용을 허용한 것은 업스트림 취약점이 아니라 해당 권한의 정상적 범위를 의미. 절대 보안 버그나 두 시스템의 동일 정책 우열로 발표하지 말 것.

이번 소유자와 요청자는 서로 구분된 Linux·DB/IAM 테스트 계정이지만, **각자 독립적으로 운영하는 제3자 인간이나 독립 기업의 실제 승인**은 아직 확인하지 않음. 원본 업스트림 서비스 개발 조직과 RISU는 독립적이나, 실행 환경과 실험 계정은 RISU가 통제함.

## 다음 단계

B27은 외부 백엔드 개발/비교 양성 대조군으로 동결. 이후 다른 원본 백엔드와, 가능하면 우리가 운영하지 않는 독립 실제 소유자·발급자에서 같은 사전 고정 성질을 시험. 실제 소유자 승인, 실행자 쓰기 권한 우회, 원격 서비스의 직접 거부, 독립적 원본 결과 감사를 연결. 3번째 새 개발 조직의 원본 배포판은 독립 평가셋으로 남겨 두고 규칙을 사후 조정하지 말 것.

### 재착수 방법
`benchmarks/p6b27/PRE_REGISTERED_PROTOCOL.md`, `SEAWEEDFS_HOLDOUT_LOCK.md`, `compare_external_backends.py`와 위 세 원본 실행 기록을 확인한다. 본 채팅이 없더라도 B27 판정 기준과 한계가 보존되어 있다.

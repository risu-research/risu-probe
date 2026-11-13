# RISU Probe P6-B25.1 | 최종 핸드오프 (2026-11-13 UTC)

**상태: 실제 인간 승인, GitHub 원격 파일 쓰기, 독립 감사 모두 성공.** 최초 B25의 미승인 상태 문서는 이 최종본으로 갱신했다. 양쪽 저장소의 `main`은 변경하지 않았다.

## 최종 증거

- **최종 실행**: https://github.com/risu-research/risu-verify/actions/runs/43355918665
- **소유자의 실제 승인**: `moon10021017`, 환경 `risu-b25-human-owner-approval`, 해당 실행 ID `43355918665`, `approved`
- **승인된 실제 변경**: https://github.com/risu-research/risu-verify/commit/26ac7506d27a76290a7a1eb945ef0f9ea6059e09
- **전체 최종 연구 보고서**: [FINAL_ACTUAL_HUMAN_REVIEW_AUDIT_20261113.md](FINAL_ACTUAL_HUMAN_REVIEW_AUDIT_20261113.md)
- **RISU Probe 소스 고정 커밋**: `669be8b14cb314acf6ba49353fa198c2415a056b`
- **소스 회귀 CI**: https://github.com/risu-research/risu-probe/actions/runs/43355766926
- **회귀 규모**: Ubuntu/Windows/macOS 각각 542 tests PASS, 별도 Python 3.14의 B25 전용 32 tests PASS

## 실제 결과

1. `risu-verify` 실험 브랜치의 사용자가 특정 GitHub Actions 실행에 직접 승인했다.
2. 비신뢰 에이전트 작업이 사용한 GitHub 읽기 전용 토큰은 임의 경로 Contents PUT을 시도했지만 HTTP 403으로 거부됐다.
3. 서명·소스 해시를 검증한 신뢰 실행기만 승인된 기존 파일 `benchmarks/p6b25/owner_only_resource.txt`에 정확히 하나의 PUT을 실행했다.
4. 기존 파일 `state=AWAITING_GITHUB_ENVIRONMENT_REVIEW`가 승인된 `state=GITHUB_HUMAN_APPROVED_BROKER_WRITE`로 변경됐다. 실제 Git 커밋의 변경 파일은 정확히 하나였다.
5. 별도의 읽기 전용 감사 코드가 GitHub 승인 기록, immutable commit, 파일 전후 blob 및 해시를 다시 조회·검증해 PASS를 반환했다.
6. 별도 POSIX UID 65534 자식에게 토큰이 전달되지 않았고, 부모 프로세스의 `/proc/.../environ` 접근도 거부됐다.

## 중간 실패 및 수정

- **최초 실패 실행**: https://github.com/risu-research/risu-verify/actions/runs/43354699656
- 승인 자체는 성공했으나 GitHub Contents API가 응답하는 줄바꿈 포함 Base64를 처리하지 못해 `MALFORMED_GITHUB_OWNER_ORIGINAL_FILE`로 거부됐다. 원본 파일 변경 없음.
- B25.1은 `CR/LF`만 제거한 후 canonical strict Base64 검사와 정확한 SHA-256/Git blob 검사를 유지한다. 독립 감사기에도 별도로 같은 호환 처리를 추가했다. 정상·변조 대조군 및 Python 3.14 테스트를 통과했다.
- 최종 `risu-verify` 워크플로는 수정된 `risu-probe` 소스를 정확한 Git 커밋과 파일 Git blob에 고정하고, 숨김 감사 파일을 아티팩트에 포함하도록 보완했다.

## 보존한 원본 GitHub Actions 아티팩트

- 신뢰 실행기 전체 결과 및 OIDC provenance: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14006286280
- 독립 감사: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14005962891
- 실제 403 차단: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14006086728
- 원본 소유자 제안서: https://github.com/risu-research/risu-verify/actions/runs/43355918665/artifacts/14005772556

## 정확한 한계

- 같은 GitHub 계정이 요청과 승인을 수행했다. **제3자 소유자·두 사람의 독립 승인은 미검증**.
- GitHub Actions 작업의 `GITHUB_TOKEN`은 저장소 단위 쓰기 권한이 있다. **파일 단위로 권한 범위를 한정하는 자격증명은 아니다**. 정확히 한 파일만 쓴다는 성질은 신뢰 코드가 집행한다.
- 비신뢰 자식에 대한 자격증명 격리는 확인했지만, 신뢰 실행기 자체의 악성 변조·runner 장악에 대한 완전한 강제 보호는 입증하지 않았다.
- 실제 외부 MCP 서버의 신규 보안 취약점을 발견한 실험이 아니다.

## 다음 B26

B25.1은 성공 사례로 동결한다. 다음 단계는 **독립된 사용자/소유자, 외부 권한 발급자, 경로 단위 또는 객체 단위 원격 권한 집행**을 결합하여 신뢰 실행기의 우회·권한 확대가 원격 자원 서비스 자체에서 거부되는지 검증하는 것이다. 개발셋과 미사용 외부 평가셋을 분리한다. B25.1의 사용자 승인·Git 커밋·실제 효과 증거는 재현 가능한 기준 사례로 활용한다.

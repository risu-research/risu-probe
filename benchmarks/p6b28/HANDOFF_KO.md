# RISU Probe P6-B28 최종 핸드오프

**2026-11-13 UTC. B28 실제 실행 성공, 원본 외부 소프트웨어 2종의 발급·사용·철회 연결 검증, RISU 설치형 3개 OS 전수 회귀 성공.** `risu-probe` 연구 브랜치에만 기록. `main`은 변경하지 않음.

## 최종 원본 증거

- [원본 OpenBao 2.7.2 + PostgreSQL 18.6 실제 실행 #43377450878](https://github.com/risu-research/risu-probe/actions/runs/43377450878)
- [원본 실행·독립 감사 아티팩트 #14015406555](https://github.com/risu-research/risu-probe/actions/runs/43377450878/artifacts/14015406555)
- [설치형 Windows/Ubuntu/macOS 전체 회귀 #43378448871](https://github.com/risu-research/risu-probe/actions/runs/43378448871)
- [최종 기술 보고서](../../docs/P6B28_ORIGINAL_ISSUER_RESOURCE_EFFECT_FINAL.md)
- 연구 브랜치: `qualification/p6b28-external-issuer-live-revocation-20261113`

## 실제로 검증한 것

1. OpenBao의 공식 개발 조직이 배포한 원본 v2.7.2 바이너리. SHA-256 공식 `checksums.txt`까지 대조한 뒤 실행. 원본 PostgreSQL 18.6에 `b28_bao_issuer`라는 동적 역할 관리 전용 계정을 설정했고, 원본 DB의 소유자는 `b28_owner`라는 별도 계정.
2. 원본 OpenBao 데이터베이스 엔진이 사용자·비밀번호·lease ID를 실제 발급. 발급 시 권한 발급자의 루트 토큰을 실행자에게 제공하지 않음.
3. OpenBao의 원본 **response wrapping**으로 자격증명을 한 번만 전달. Linux UID 65534인 비신뢰 자식이 `POST /sys/wrapping/unwrap`을 호출해 성공(HTTP 200), 다시 개봉 시 HTTP 400, 소비된 토큰으로 자격증명 재발급 요청 시 HTTP 403.
4. 별도 자식은 RISU 게이트웨이를 완전히 우회해 원본 PostgreSQL에 직접 로그인한 후 **14개의 무단 SQL**을 실행. 전부 거부되거나 영향 0행. 승인된 정확한 1개 행의 `WAITING / ORIGINAL APPROVED` → `APPROVED / APPROVED CONTENT` 변경은 1행 성공, 나머지 2행은 그대로.
5. 동일한 실제 DB 자격증명으로 재실행하면 결과 0행. **OpenBao 운영자가 실제 lease를 철회한 후**, 동적 DB 역할이 소멸하고 실행자가 기존 비밀번호로 새 PostgreSQL 연결을 만드는 시도도 거부됨.
6. 별도 독립 감사 코드는 원본 DB의 실제 행·PG 시스템 카탈로그·RLS 정책·역할 및 OpenBao 본래의 엔진/역할 정보를 다시 조회해 PASS. 임의 변경한 긍정 결과는 거부.
7. 원본 GitHub 아티팩트의 비밀값 보존 금지 검사 통과. 루트 토큰·DB 비밀번호·포장 토큰은 ZIP/보고서에 포함되지 않음.

## 재사용 가능한 RISU Probe 기능

```bash
risu-probe verify-mcp-external-authority \
  --evidence-dir ./original-evidence \
  --out certificate.json
```

이는 **수집된 원본 증거의 오프라인 일관성 검증**임. 새로운 실시간 외부 승인·서버 상태를 조회했다고 주장하지 않음. 서명·원본 코드·실제 GitHub 아티팩트는 따로 연결하여 검증.

- 설치형 전체 테스트 **Ubuntu 569 / Windows 569 / macOS 569**, 모두 성공.
- 전용 B28 원본 증거 테스트 **각 11건**과 변경된 파일·승인 범위·권한 발급자·재사용·철회·인간 소유자 주장 변조 대조군 성공.
- CLI와 패키징 모두 `pyproject.toml`에 포함, 실제 wheel 설치 후 실행 검증.
- 독립적인 실제 인간 소유자 승인·외부 운영 조직·자격증명의 수령인 암호학적 귀속은 증명되지 않았으므로 인증서가 `false`로 판정.

## 중간 실패도 중요한 발견

초기 `num_uses=1` OpenBao 토큰으로 직접 동적 DB 자격증명을 받는 방식은 HTTP 400으로 실패. 토큰 소진과 자식 lease 유효성 문제였고, 이를 임의로 성공 처리하지 않았음. [방법론 수정 기록](AMENDMENT_WRAPPED_LEASE_NOT_ONE_USE_ISSUER_TOKEN.md) 참고. 수정 후에도 권한을 넓힌 것이 아니라 **포장된 응답의 1회 전달**, **동적 DB 자격증명의 lease**, **PG 원본 행에 대한 1회 상태 변경**을 별개 집행·검증하는 구조로 발전.

## 본질적인 연구적 결론

독립 개발 조직이 만든 원본 OpenBao와 PostgreSQL에서 실제 발급 → 1회 전달 → 직접 원본 DB 실행 → 14개 무단 요청 거부 → 정확한 상태 변경 → 재사용 거부 → 원래 발급자의 철회 → 새 로그인 차단을 관찰함.

이는 B25의 **실제 인간 승인**, B26의 **자체 제작 서비스 자원 측 집행**, B27의 **두 원본 외부 자원 서비스의 정책 차이**에서 더 발전한 외부 발급자–자원 서비스 연결 증거다. 단, **B25 승인과 B28 실행이 동일한 새 동의 행위였다고 연결해서는 안 됨**. 현재 실제 승인자는 CI 실험 관리자이고 B28 발급·실행을 두 외부 조직이 독립 운영한 것은 아님.

## 재착수 / 다음 문제

- B28을 원본 검증된 **개발 양성 대조군**으로 동결하고, 다른 새로운 서비스와 발급자로 독립 평가할 것.
- 다음 결정적 경계는 **서로 실제로 다른 인간이나 외부 기관이 각각 관리하는 계정·권한 발급자·자원 서비스**를 확보해, 사전 승인 서명/로그와 실제 권한·원본 효과를 연결하는 것. 제3자 승인 없이 독립 소유자라 표현하지 말 것.
- 오프라인 증거가 `true`인 속성만 구체적으로 쓰고, 외부 운영·수령인 신원 귀속·인간 승인 속성의 `false`를 정확히 보존할 것.

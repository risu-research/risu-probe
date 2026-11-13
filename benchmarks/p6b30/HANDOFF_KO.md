# RISU Probe P6-B30.2 최종 핸드오프 (2026-11-13)

**완료: 별도 외부 사람 없이 새로운 원본 GitHub 승인-실제 변경 연결 검증 및 4개 외부 원본 사례의 주장별 증거 판정 알고리즘을 구현하고 검증함.** 모두 qualification 브랜치. RISU Probe 및 RISU Verify main 변경 없음.

## 가장 중요한 실제 증거

1. B25의 원본 GitHub Actions 실행 #43355918665와 그 승인된 소스 커밋 e9409d8ef4a6a71a3a93705909fe5c777d014bbc를 원본 GitHub REST로 새로 검증.
2. 실제 변경 커밋 26ac7506d27a76290a7a1eb945ef0f9ea6059e09의 **유일한 부모 커밋이 승인 실행 소스 SHA와 정확히 같음**.
3. 그 커밋은 정확히 한 파일 benchmarks/p6b25/owner_only_resource.txt를 변경했고, 변경 전후 원본 바이트를 읽어 SHA-256 + Git blob SHA1을 독립 재계산. 소유자 제안서의 정확한 기존 상태·바뀐 내용과 일치.
4. 별도 실제 GitHub 승인 이벤트도 해당 원본 실행/환경에서 발견. 단 B25의 승인자와 실행자는 같은 실제 GitHub 계정이므로 외부 독립 소유자 승인이라고 주장하지 않음.
5. 임의로 다른 GitHub 실행/저장소/부모 커밋/두 번째 파일/다른 파일 내용/리뷰어를 결합하면 새 검증기가 거부.

**실제 원본 GitHub 소스-효과 검증 최종 실행**
https://github.com/risu-research/risu-probe/actions/runs/43441570914

**원본 승인 및 파일 효과 인증서 ZIP 아티팩트**
https://github.com/risu-research/risu-probe/actions/runs/43441570914/artifacts/14044414554

## 더 중요한 일반화 실험

기존 B25·B27·B28·B29의 원본 GitHub Actions 아티팩트를 각자의 원본 실행에서 다시 가져와 네 개 서로 다른 실제 자원/작업으로 구분하여 증거를 결합하는 새 알고리즘을 검증.

- B25 GitHub 파일: 정확한 객체·내용·실제 상태 변경은 검증. 진짜 독립 외부 소유자 등은 미입증.
- B27 PostgreSQL 행: 객체·내용·기존 상태·반복 방지·철회·별도 감사 검증.
- B27 SeaweedFS S3: 객체 범위와 철회·감사 검증. **승인된 객체에 다른 바이트 쓰기와 반복 PutObject는 실제로 성공했으므로 해당 정책이 내용·1회 사용까지 제한한다는 주장은 반증됨**. 이는 의도된 S3 IAM 접근 범위의 차이이지 새 업스트림 취약점이 아님.
- B28 OpenBao+PostgreSQL: 원본 동적 발급, 1회 전달, 특정 내용, 전이, 반복 방지, lease 철회, 실제 효과 독립 감사 모두 검증. 독립 인간 소유자 승인은 미입증.

이제 각각의 주장별 결과는 다음 3상태를 명시함.

- VERIFIED: 해당 자원과 실행에 대한 실제 원본 긍정 증거.
- REFUTED: 그 주장을 반박하는 실제 원본 반례 존재.
- UNVERIFIED: 원본 증거가 이 입력 집합에서 확보되지 않음. 반증이 아님.

서로 다른 연구의 참인 증거를 하나로 합쳐 허위 승인으로 판정하는 것을 금지. 특히 B25의 인간 승인과 B28의 동적 자격증명/실제 실행을 합쳐 하나의 소유자 승인이라고 주장하는 경우 거부. 이 네 사례는 서로 다른 원본 resource subject임.

**4개 사례의 삼상태 판정 최종 GitHub 실행**
https://github.com/risu-research/risu-probe/actions/runs/43441533953

**최종 삼상태 판정 아티팩트**
https://github.com/risu-research/risu-probe/actions/runs/43441533953/artifacts/14045972879

## 구현된 실제 RISU Probe 명령

원본 GitHub 승인과 특정 자원의 실제 Git 변경 이력 검증:

    risu-probe verify-mcp-effect-closure \
      --repo risu-research/risu-verify --run-id 43355918665 \
      --environment risu-b25-human-owner-approval \
      --proposal-path benchmarks/p6b25/OWNER_PROPOSED_REQUEST.json \
      --effect-commit 26ac7506d27a76290a7a1eb945ef0f9ea6059e09 \
      --out b30-effect-closure.json

기존 실제 연구 사례 4종의 승인·권한·실제 효과를 다른 작업으로 섞지 않고 비교:

    risu-probe compare-mcp-claim-sufficiency \
      --b30 original_b25_effect_closure.json \
      --b29 b25-original-github-self-review.json \
      --b27 independent_capability_matrix.json \
      --b28 .b28-record-certificate.json \
      --out b30-obligations.json

새 핵심 파일:
- src/risu_mcp_effect_closure.py
- src/risu_mcp_claim_sufficiency.py
- tests/test_p6b30_effect_closure.py
- tests/test_p6b30_claim_sufficiency.py
- docs/P6B30_CLAIM_SPECIFIC_EFFECT_CLOSURE_FINAL.md

## 전체 제품 회귀

최종 설치형 원본 실행: https://github.com/risu-research/risu-probe/actions/runs/43441570914

Ubuntu, Windows, macOS 모두 PASS. 실제 B25 원본 API 실험/원본 변경 공격적 대조군 별도 PASS. 4개 기존 원본 소스의 주장별 검증과 원본 반례 변조 테스트 PASS.

## 연구적 정확한 해석

in-toto는 이미 아티팩트 입력/출력과 단계 간 해시 체인을 검증하고, Sigstore는 서명 검증 및 발급자 신원을 검증함. RISU B30의 구현은 기존 기술을 대체하거나 새 수학적 증명 원리를 만든 것이 아니라, **특정 실행의 소유자 승인 주장과 그 자원의 실제 변경이 같은 증거에 의해 입증되는지**를 진단하는 좁고 재현 가능한 검증기임.

이번 네 사례는 규칙 개발 중 참조한 **개발·회귀 사례**이며 새로운 숨김 평가셋이라고 부르면 안 됨. B30의 네 사례 매트릭스는 과거 GitHub 원본 아티팩트의 오프라인 집계이며, 모든 외부 자원에 직접 실시간 연결한 검증은 아님. 기존 B25 별도 독립 감사 자료는 존재하지만 새 네 소스 매트릭스에 포함되지 않았으므로 해당 항목이 UNVERIFIED로 뜰 수 있음.

원본 GitHub 승인+커밋 부모+파일 바이트의 일치는 강한 출처 연결이지만 그 자체로 **승인이 변경을 초래했다는 인과**나 **제3자 자연인의 승인을 뜻하지 않음**. B30 전체 결합 증명은 아직 별도의 암호학적 서명 체인이 없고, 신뢰 CI/운영자 침해에 대한 완전한 보호는 아님.

## 다음 업그레이드도 외부 협력 없이 가능

B31에서는 in-toto/Sigstore **기존 서명 검증기와 신뢰 루트**를 사용하여 검증된 원본 증거만 받아들이게 개선하는 것이 다음 최선. 그리고 현재 B25~B30 개발 사례와 분리한 새 외부 GitHub Actions/Sigstore 아티팩트 평가셋을 사전에 동결하고, 잘못된 증거 결합 탐지·오탐·놓침을 실제로 평가해야 함. 외부 사람 협력·수동 승인·실제 타인 계정은 계속 후순위.

외부 이메일/메시지는 보내지 않았음. GitHub main을 변경하지 않음.

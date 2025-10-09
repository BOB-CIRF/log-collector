## log-collector
### 🎨 Git Commit Convention
- **커밋 메세지 양식**
  ```
  [TYPE/ISSUE] 간결한 제목
  ex. [FEAT/KAN-47] CloudTrail 수집 기능 추가
  ```
  - **TYPE**: 아래 표의 유형(대문자)
  - **ISSUE**: 이슈/티켓 키(예: KAN-47)

| TYPE         | 용도 설명                                | 예시 Prefix           |
| ------------ | ------------------------------------ | ------------------- |
| **FEAT**     | 새로운 기능 추가                            | `[FEAT/KAN-47]`     |
| **FIX**      | 버그 수정                                | `[FIX/KAN-102]`     |
| **DOCS**     | 문서 수정(README, 가이드, 주석 등)             | `[DOCS/KAN-58]`     |
| **STYLE**    | 코드 포맷/세미콜론/공백 등, 로직 변경 없음        | `[STYLE/KAN-63]`    |
| **REFACTOR** | 리팩터링(동작 동일, 구조 개선/성능 향상)             | `[REFACTOR/KAN-75]` |
| **TEST**     | 테스트 코드 추가/수정                         | `[TEST/KAN-84]`     |
| **CHORE**    | 빌드/배포/의존성/스크립트 등 개발환경(패키지 매니저 포함) 변경 | `[CHORE/KAN-19]`    | 


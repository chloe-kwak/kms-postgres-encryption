# KMS PostgreSQL 암복호화 솔루션

디아모(Diamo)에서 AWS KMS로 데이터베이스 암복호화를 마이그레이션하는 프로덕션 레디 솔루션

## 🎯 핵심 특징

✅ **키 분리 관리** - DEK를 KMS로 암호화하여 안전하게 보관
✅ **디아모 방식 유지** - View로 복호화, 테이블로 암호화된 데이터 조회
✅ **비용 절감 99%** - 세션당 1회만 KMS 호출 ($14 → $0.29/월)
✅ **고성능** - DB 내부 pgcrypto 처리 (2-5ms, 75배 빠름)
✅ **보안 강화** - UNLOGGED TABLE, 1분 TTL, 감사 로그

## 📋 시스템 구성

```
애플리케이션 (코드 수정 최소)
    ↓
PostgreSQL (pgcrypto + DEK 캐싱)
    ↓ 세션당 1회만 Lambda 호출
AWS Lambda
    ↓
AWS KMS (키 분리 관리)
```

## 🚀 빠른 시작

### 1. Lambda 함수 배포

```bash
# 환경 변수 설정
cp .env.example .env
vi .env  # AWS_REGION, KMS_KEY_ID, LAMBDA_ROLE_ARN, DB_HOST 설정

# Lambda 배포
source .env
./scripts/deploy-lambda.sh
```

### 2. PostgreSQL 설정

```bash
# 보안 강화 패턴 적용
psql -h $DB_HOST -U postgres -d postgres -f sql/secure-pgcrypto-pattern.sql

# Lambda ARN 업데이트 (출력된 ARN으로)
vi sql/secure-pgcrypto-pattern.sql
# 'arn:aws:lambda:ap-northeast-2:123456789012:function:kms-decrypt' 수정
```

### 3. DEK 초기화

```bash
psql -h $DB_HOST -U admin -d postgres << EOF
SELECT initialize_dek('users_ssn_key', 'SSN encryption');
SELECT initialize_dek('users_cc_key', 'Credit card encryption');
EOF
```

### 4. 테스트

```bash
# 로컬 테스트 (Lambda/KMS 없이)
python3 test/test_encryption.py

# PostgreSQL 통합 테스트 (DB 필요)
psql -h $DB_HOST -U app_user -d postgres -f test/local-test.sql
```

## 💻 사용 방법

### 데이터 삽입 (자동 암호화)

```typescript
// Trigger가 자동으로 암호화
await db.query(
  'INSERT INTO users_secure (username, email, ssn, credit_card) VALUES ($1, $2, $3, $4)',
  ['john', 'john@example.com', '123-45-6789', '1234-5678-9012-3456']
);
```

### 조회 - 암호화된 데이터

```typescript
// app_user: 암호화된 데이터만 조회
const result = await db.query('SELECT ssn FROM users_secure WHERE username = $1', ['john']);
// ssn: 'kY8N4G99ga03nZSlluJKL37BynRN6biYZP+l0...' (Base64 암호문)
```

### 조회 - 복호화된 데이터

```typescript
// admin: 복호화된 데이터 조회 (View 사용)
const result = await adminDb.query(
  'SELECT ssn FROM users_secure_decrypted WHERE username = $1',
  ['john']
);
// ssn: '123-45-6789' (평문)
// 첫 쿼리: ~150ms (Lambda 호출)
// 이후 쿼리: ~2ms (캐시 히트)
```

## 🔒 보안 특징

### 키 분리 관리

```
CMK (Customer Master Key)
 └─ AWS KMS HSM에만 존재 (절대 외부로 안 나옴)
    │
    ↓ DEK를 암호화/복호화
DEK (Data Encryption Key)
 └─ DB에 암호화된 상태로 저장
    │
    ↓ 실제 데이터를 암복호화
암호화된 데이터
 └─ DB에 저장
```

### 보안 강화 기능

- ✅ **UNLOGGED TABLE** - DEK 캐시가 백업에 포함 안 됨
- ✅ **TTL 1분** - 평문 DEK 노출 시간 최소화
- ✅ **SECURITY DEFINER** - 직접 접근 차단
- ✅ **감사 로그** - 모든 DEK 접근 기록
- ✅ **의심 활동 탐지** - 5분에 100회 이상 자동 알람

### 보안 평가

| 방식 | 보안 점수 | 평가 |
|------|----------|------|
| 디아모 | 6/10 | 키가 DB에 있어 위험 |
| KMS (매번 호출) | 10/10 | 최고 보안 |
| **KMS + pgcrypto (캐싱)** | **8/10** | **균형잡힌 보안** ⭐ |

상세 분석: [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md)

## 📊 비용 비교

### 시나리오: 일일 100,000번 복호화

| 방식 | Lambda 호출 | 월 비용 | 절감 |
|------|-----------|--------|------|
| 매번 호출 | 3,000,000회 | $14.40 | - |
| **캐싱 (세션당 1회)** | **90,000회** | **$0.29** | **98%** ⭐ |

### 성능 비교

| 방식 | 복호화 시간 | 처리량 |
|------|-----------|--------|
| 매번 Lambda 호출 | 100-300ms | 6건/초 |
| **pgcrypto (캐싱)** | **2-5ms** | **500건/초** ⭐ |

## 📁 프로젝트 구조

```
kms-postgres-encryption/
├── README.md                          이 파일
├── DEK-EXPLAINED.md                   DEK 개념 설명
├── SECURITY-ANALYSIS.md               보안 분석
├── .env.example                       환경 변수 템플릿
│
├── lambda/
│   ├── kms-decrypt/                   KMS 복호화 Lambda
│   └── kms-encrypt/                   KMS 암호화 Lambda
│
├── sql/
│   └── secure-pgcrypto-pattern.sql    최종 패턴 (보안 강화)
│
├── scripts/
│   ├── deploy-lambda.sh               Lambda 자동 배포
│   ├── setup-database.sh              PostgreSQL 설정
│   └── test-encryption.sh             통합 테스트
│
└── test/
    ├── test_encryption.py             Python 로컬 테스트
    └── local-test.sql                 PostgreSQL 테스트
```

## 🔄 마이그레이션 (디아모 → KMS)

### Phase 1: 병렬 운영

```sql
-- 기존 컬럼 유지, 새 컬럼 추가
ALTER TABLE users ADD COLUMN ssn_kms TEXT;

-- 신규 데이터는 KMS로
-- 기존 데이터는 점진적 재암호화
```

### Phase 2: 배치 마이그레이션

```sql
UPDATE users
SET ssn_kms = encrypt_local(diamo_decrypt(ssn_diamo), 'users_ssn_key')
WHERE ssn_kms IS NULL;
```

### Phase 3: 컬럼 교체

```sql
ALTER TABLE users DROP COLUMN ssn_diamo;
ALTER TABLE users RENAME COLUMN ssn_kms TO ssn;
```

## 🛠️ AWS 리소스 준비

### 1. KMS Key 생성

```bash
aws kms create-key --description "Database encryption" --region ap-northeast-2
aws kms create-alias --alias-name alias/db-encryption --target-key-id <KEY_ID>
```

### 2. Lambda IAM 역할

```bash
aws iam create-role --role-name lambda-kms-role \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy --role-name lambda-kms-role \
  --policy-arn arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser
```

### 3. RDS Lambda 통합 (Aurora PostgreSQL)

```bash
aws rds add-role-to-db-cluster \
  --db-cluster-identifier your-cluster \
  --role-arn arn:aws:iam::ACCOUNT:role/rds-lambda-invoke \
  --feature-name Lambda
```

## 📈 모니터링

### 캐시 효율 확인

```sql
SELECT
  key_name,
  COUNT(*) as sessions,
  AVG(access_count) as avg_access
FROM temp_dek_cache
WHERE expires_at > NOW()
GROUP BY key_name;
```

### 의심 활동 탐지

```sql
SELECT * FROM check_suspicious_activity();
-- 5분에 100회 이상 복호화 시도 자동 탐지
```

### 감사 로그

```sql
SELECT
  event_type,
  user_name,
  COUNT(*) as count,
  DATE(timestamp) as date
FROM security_audit
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY event_type, user_name, DATE(timestamp)
ORDER BY date DESC;
```

## ❓ FAQ

### Q: DEK가 뭔가요?

Data Encryption Key의 약자로, 실제로 데이터를 암복호화하는 작업용 키입니다.
상세 설명: [DEK-EXPLAINED.md](DEK-EXPLAINED.md)

### Q: DEK 캐싱이 안전한가요?

제한적으로 안전합니다. UNLOGGED TABLE, 1분 TTL, 접근 제어, 감사 로그로 보완합니다.
상세 분석: [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md)

### Q: 매번 KMS 호출하는 방식과 차이는?

| 항목 | 매번 호출 | DEK 캐싱 |
|------|----------|---------|
| 보안 | 10/10 | 8/10 |
| 비용 | $14/월 | $0.29/월 |
| 성능 | 150ms | 2ms |

금융/의료: 매번 호출, 일반 기업: DEK 캐싱 추천

## 📞 지원

- GitHub Issues: 문제 리포트
- AWS KMS 문서: https://docs.aws.amazon.com/kms/
- PostgreSQL pgcrypto: https://www.postgresql.org/docs/current/pgcrypto.html

## 📝 라이선스

MIT License

---

**디아모를 KMS로 안전하게, 경제적으로 마이그레이션하세요!** 🚀

# 보안 분석: pgcrypto + DEK 캐싱 방식

## 🔍 보안 우려사항 분석

### ⚠️ 잠재적 보안 취약점

#### 1. 평문 DEK가 메모리에 존재

**우려:**
```sql
-- temp_dek_cache 테이블에 평문 DEK 저장 (5분 TTL)
temp_dek_cache:
  session_id: '12345'
  plaintext_dek: '\x4a3f2e1d...' (평문 32 bytes)
  expires_at: '2024-02-05 10:35:00'
```

**위험 시나리오:**
- ❌ DB 관리자가 직접 DEK 테이블 조회
- ❌ SQL Injection으로 캐시 테이블 접근
- ❌ 메모리 덤프로 DEK 추출
- ❌ 백업 파일에 캐시 포함

---

#### 2. 세션 하이재킹

**우려:**
```
공격자가 세션을 탈취하면 → DEK 캐시 접근 가능 → 데이터 복호화 가능
```

---

#### 3. 권한 에스컬레이션

**우려:**
```sql
-- app_user가 권한 상승하면?
ALTER USER app_user WITH SUPERUSER;  -- 공격자가 실행
-- → temp_dek_cache 직접 조회 가능
```

---

## ✅ 실제 보안 수준 평가

### 보안 계층 분석

#### Layer 1: AWS KMS (최상위 - 가장 안전) ⭐⭐⭐⭐⭐
```
✅ CMK는 절대 노출되지 않음 (HSM 내부)
✅ IAM으로 접근 제어
✅ CloudTrail로 모든 API 기록
✅ 키 삭제 시 30일 대기
```

#### Layer 2: Lambda (안전) ⭐⭐⭐⭐
```
✅ 실행 역할로 KMS 접근 제어
✅ VPC 격리 가능
✅ CloudWatch Logs 모니터링
⚠️ Lambda 코드가 노출되면 로직 파악 가능
```

#### Layer 3: dek_store (안전) ⭐⭐⭐⭐
```
✅ 암호화된 DEK만 저장 (평문 DEK 없음)
✅ 테이블 권한으로 접근 제어
✅ 백업 시 암호화된 채로 백업
⚠️ 하지만 KMS 권한 있으면 복호화 가능
```

#### Layer 4: temp_dek_cache (취약) ⚠️⚠️
```
⚠️ 평문 DEK가 메모리에 존재 (5분)
⚠️ DB 관리자가 조회 가능
⚠️ 메모리 덤프 시 노출 가능
⚠️ 백업 파일에 포함될 수 있음
```

#### Layer 5: users 테이블 (안전) ⭐⭐⭐⭐
```
✅ 암호화된 데이터만 저장
✅ 백업 시 암호화된 채로 백업
⚠️ 하지만 DEK 있으면 복호화 가능
```

---

## 🆚 디아모 vs KMS 보안 비교

### 디아모 (기존 방식)

| 항목 | 보안 수준 |
|------|----------|
| 키 저장 | DB에 암호화된 키 저장 ⭐⭐⭐ |
| 키 관리 | 수동 관리 (사람이 접근) ⚠️⚠️ |
| 암복호화 | DB 내부 처리 ⭐⭐⭐⭐ |
| 감사 로그 | DB 로그만 ⚠️⚠️ |
| 키 노출 위험 | 관리자가 키 추출 가능 ⚠️⚠️ |

### KMS + pgcrypto (제안 방식)

| 항목 | 보안 수준 |
|------|----------|
| 키 저장 | KMS HSM (최고 수준) ⭐⭐⭐⭐⭐ |
| 키 관리 | AWS 자동 관리 + IAM ⭐⭐⭐⭐⭐ |
| 암복호화 | DB 내부 처리 ⭐⭐⭐⭐ |
| 감사 로그 | DB + CloudTrail ⭐⭐⭐⭐⭐ |
| 키 노출 위험 | **DEK 캐시 노출 가능** ⚠️⚠️⚠️ |

### 핵심 차이

```
디아모:
- 마스터 키가 DB에 암호화되어 저장
- 관리자가 키 파일 접근 가능
- 키 탈취 시 모든 데이터 노출

KMS + pgcrypto:
- 마스터 키(CMK)는 KMS HSM에만 존재 (노출 불가)
- DEK만 캐시에 존재 (5분 TTL)
- 캐시 탈취 시 해당 세션 데이터만 노출
```

---

## 🛡️ 보안 강화 방안

### 방안 1: 캐시 보안 강화 (추천) ⭐

#### 1-1. 메모리 전용 캐시 (UNLOGGED TABLE)

```sql
-- 디스크에 기록하지 않음 → 백업 불포함
CREATE UNLOGGED TABLE temp_dek_cache (
  session_id TEXT,
  key_name VARCHAR(100),
  plaintext_dek BYTEA,
  expires_at TIMESTAMP,
  PRIMARY KEY (session_id, key_name)
);

-- 장점:
-- ✅ 백업 파일에 포함 안 됨
-- ✅ WAL에 기록 안 됨
-- ✅ 성능 향상

-- 단점:
-- ⚠️ 서버 재시작 시 캐시 삭제 (재구축 필요)
-- ⚠️ Replication에 복제 안 됨
```

#### 1-2. TTL 단축 (5분 → 1분)

```sql
-- 노출 위험 시간 최소화
INSERT INTO temp_dek_cache (...)
VALUES (..., NOW() + INTERVAL '1 minute');  -- 5분 → 1분
```

#### 1-3. 접근 제어 강화

```sql
-- temp_dek_cache 직접 조회 금지
REVOKE ALL ON temp_dek_cache FROM PUBLIC;
REVOKE ALL ON temp_dek_cache FROM app_user, admin, auditor;

-- 함수만 접근 가능
GRANT SELECT, INSERT, DELETE ON temp_dek_cache TO decrypt_local_func;

-- get_plaintext_dek() 함수에만 SECURITY DEFINER 부여
CREATE OR REPLACE FUNCTION get_plaintext_dek(...)
SECURITY DEFINER  -- 함수 소유자 권한으로 실행
SET search_path = public
AS $$
  -- 함수 내부에서만 temp_dek_cache 접근
$$;
```

### 방안 2: DEK 암호화 저장 (메모리에도 암호화)

```sql
-- 세션별 암호화 키 생성
CREATE OR REPLACE FUNCTION get_session_key()
RETURNS BYTEA AS $$
  -- 세션별 고유 키 생성 (메모리 전용)
  SELECT digest(
    pg_backend_pid()::TEXT ||
    current_user ||
    gen_random_uuid()::TEXT,
    'sha256'
  );
$$ LANGUAGE SQL;

-- DEK를 세션 키로 2차 암호화하여 캐시 저장
CREATE TABLE temp_dek_cache (
  session_id TEXT,
  key_name VARCHAR(100),
  encrypted_dek_cache BYTEA,  -- 세션 키로 암호화됨
  session_key_hint BYTEA,     -- 키 복구용 힌트
  expires_at TIMESTAMP
);

-- 장점:
-- ✅ 메모리에도 암호화된 상태
-- ✅ 캐시 테이블 조회해도 평문 DEK 없음

-- 단점:
-- ⚠️ 복잡도 증가
-- ⚠️ 세션 키 관리 필요
```

### 방안 3: 캐시 없이 매번 호출 (가장 안전)

```sql
-- 캐시 사용 안 함 → 매번 Lambda 호출
-- = Pattern 1 (매번 Lambda 호출 방식)

-- 장점:
-- ✅ 평문 DEK가 DB에 전혀 없음
-- ✅ 가장 안전

-- 단점:
-- ⚠️ 비용 증가 (99%)
-- ⚠️ 성능 저하 (75배 느림)
```

### 방안 4: 하이브리드 접근 (권장) ⭐⭐⭐

```sql
-- 민감도에 따라 다른 방식 사용

-- 극히 민감한 데이터 (주민번호, 카드번호)
-- → 캐시 없이 매번 Lambda 호출
CREATE FUNCTION decrypt_critical(...)
  -- 캐시 사용 안 함
  -- Lambda 직접 호출

-- 일반 민감 데이터 (주소, 전화번호)
-- → 캐시 사용 (1분 TTL)
CREATE FUNCTION decrypt_standard(...)
  -- 캐시 사용 (TTL 1분)

-- 사용 예시:
CREATE VIEW users_decrypted AS
SELECT
  id,
  username,
  decrypt_critical(ssn) AS ssn,        -- 매번 Lambda 호출
  decrypt_standard(address) AS address  -- 캐시 사용
FROM users;
```

---

## 🔒 추가 보안 조치

### 1. Database 암호화

```bash
# RDS 암호화 활성화 (at-rest encryption)
aws rds create-db-instance \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:...

# 장점:
# ✅ 디스크 레벨 암호화
# ✅ 백업 자동 암호화
# ✅ 스냅샷 암호화
```

### 2. 네트워크 격리

```bash
# Lambda를 Private Subnet에 배포
# RDS도 Private Subnet에 배포
# 외부 인터넷 차단

# VPC Flow Logs 활성화
aws ec2 create-flow-logs \
  --resource-type VPC \
  --traffic-type ALL
```

### 3. 감사 로그 강화

```sql
-- 모든 DEK 접근 기록
CREATE OR REPLACE FUNCTION audit_dek_access()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO security_audit (
    event_type,
    user_name,
    session_id,
    key_name,
    ip_address,
    timestamp
  ) VALUES (
    TG_OP,
    current_user,
    pg_backend_pid()::TEXT,
    NEW.key_name,
    inet_client_addr(),
    NOW()
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_dek_cache
AFTER INSERT OR UPDATE OR DELETE ON temp_dek_cache
FOR EACH ROW EXECUTE FUNCTION audit_dek_access();
```

### 4. 런타임 모니터링

```sql
-- 의심스러운 접근 탐지
SELECT
  session_id,
  user_name,
  COUNT(*) as access_count,
  ARRAY_AGG(DISTINCT key_name) as keys_accessed
FROM security_audit
WHERE timestamp >= NOW() - INTERVAL '5 minutes'
GROUP BY session_id, user_name
HAVING COUNT(*) > 100  -- 5분에 100회 이상 접근
ORDER BY access_count DESC;

-- 알람 설정
CREATE OR REPLACE FUNCTION check_suspicious_activity()
RETURNS void AS $$
DECLARE
  suspicious_count INT;
BEGIN
  SELECT COUNT(*) INTO suspicious_count
  FROM security_audit
  WHERE timestamp >= NOW() - INTERVAL '5 minutes'
  GROUP BY session_id
  HAVING COUNT(*) > 100;

  IF suspicious_count > 0 THEN
    -- SNS 알람 전송
    PERFORM aws_lambda.invoke(
      'arn:aws:lambda:...:function:send-security-alert',
      json_build_object(
        'alert_type', 'SUSPICIOUS_ACTIVITY',
        'message', 'Abnormal DEK access detected'
      )::TEXT
    );
  END IF;
END;
$$ LANGUAGE plpgsql;
```

---

## 📊 위험 평가 매트릭스

### 공격 시나리오별 영향도

| 공격 시나리오 | 디아모 | KMS+pgcrypto (캐시) | KMS (캐시 없음) |
|-------------|--------|-------------------|----------------|
| **DB 관리자 악의적 접근** | ⚠️⚠️⚠️ 마스터 키 추출 가능 | ⚠️⚠️ DEK 캐시 조회 가능 (5분) | ✅ 불가능 |
| **SQL Injection** | ⚠️⚠️ 키 테이블 접근 가능 | ⚠️ 캐시 접근 가능 (권한 필요) | ✅ 불가능 |
| **백업 파일 탈취** | ⚠️⚠️⚠️ 키 포함 | ⚠️ UNLOGGED면 불포함 | ✅ 키 없음 |
| **메모리 덤프** | ⚠️⚠️ 키 추출 가능 | ⚠️⚠️ DEK 추출 가능 | ✅ DEK 없음 |
| **Lambda 코드 노출** | N/A | ⚠️ 로직 파악 가능 | ⚠️ 로직 파악 가능 |
| **KMS 권한 탈취** | N/A | ⚠️⚠️⚠️ 모든 DEK 복호화 | ⚠️⚠️⚠️ 모든 데이터 복호화 |

### 보안 점수 (10점 만점)

| 방식 | 점수 | 평가 |
|------|------|------|
| **디아모** | 6/10 | 키가 DB에 있어 위험 |
| **KMS (캐시 없음)** | 10/10 | 최고 수준 보안 |
| **KMS + pgcrypto (캐시)** | 7/10 | 캐시 노출 위험 있으나 통제 가능 |
| **KMS + pgcrypto (UNLOGGED + 1분 TTL)** | 8/10 | 보안 강화 시 우수 |
| **KMS + 하이브리드** | 9/10 | 민감도별 차등 적용 시 최적 |

---

## 🎯 최종 권장사항

### 시나리오별 추천 패턴

#### 1. 금융권, 의료 (최고 보안)
```
✅ Pattern: 캐시 없이 매번 Lambda 호출
✅ 또는: 하이브리드 (극민감 데이터만 캐시 없음)
✅ 비용: $9.60/월 (10만건 기준)
✅ 보안: 10/10
```

#### 2. 일반 기업 (균형)
```
✅ Pattern: pgcrypto + DEK 캐싱 (UNLOGGED, 1분 TTL)
✅ 비용: $0.01/월 (10만건 기준)
✅ 보안: 8/10
✅ 추가 조치:
   - UNLOGGED TABLE
   - TTL 1분
   - 감사 로그 강화
   - 런타임 모니터링
```

#### 3. 스타트업, 소규모 (비용 우선)
```
✅ Pattern: pgcrypto + DEK 캐싱 (기본)
✅ 비용: $0.01/월
✅ 보안: 7/10
✅ 디아모 대비 보안 수준 향상
```

---

## ✅ 결론

### 질문: pgcrypto + DEK 캐싱 방식에 보안 취약성이 있나요?

**답변:**

1. **있습니다 ⚠️**
   - 평문 DEK가 5분간 메모리에 존재
   - DB 관리자가 접근 가능 (이론상)

2. **하지만 통제 가능합니다 ✅**
   - UNLOGGED TABLE 사용
   - TTL 단축 (1분)
   - 접근 제어 강화
   - 감사 로그 + 모니터링

3. **디아모보다 안전합니다 ✅**
   - 마스터 키(CMK)는 KMS HSM에만 존재
   - DEK만 캐시에 있고 5분 후 자동 삭제
   - CloudTrail로 모든 접근 추적

4. **최고 보안이 필요하면 ✅**
   - 캐시 없이 매번 Lambda 호출 (Pattern 1)
   - 또는 하이브리드 방식 (민감도별 차등)

### 최종 추천

**대부분의 경우: pgcrypto + DEK 캐싱 (보안 강화)**
- UNLOGGED TABLE
- TTL 1분
- 감사 로그 + 알람

**금융/의료: 하이브리드 방식**
- 극민감: 매번 Lambda 호출
- 일반 민감: 캐시 사용

**비용 대비 보안이 가장 균형잡힌 방식입니다.** ⭐

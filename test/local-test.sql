-- =====================================================
-- 로컬 테스트 (Lambda/KMS 없이)
-- =====================================================
--
-- 이 스크립트는 Lambda/KMS 없이 pgcrypto만으로
-- 암복호화 패턴을 테스트합니다.
--
-- 실행: psql -U postgres -d postgres -f test/local-test.sql
--
-- =====================================================

\echo '=== KMS 암복호화 로컬 테스트 시작 ==='
\echo ''

-- pgcrypto 설치
CREATE EXTENSION IF NOT EXISTS pgcrypto;

\echo '✓ pgcrypto extension 설치 완료'
\echo ''

-- =====================================================
-- 1. 테스트용 DEK 생성 (실제로는 KMS에서 생성)
-- =====================================================

\echo '=== Step 1: DEK 생성 (KMS 시뮬레이션) ==='

-- DEK 저장소
CREATE TABLE IF NOT EXISTS test_dek_store (
  key_name VARCHAR(100) PRIMARY KEY,
  dek BYTEA NOT NULL,  -- 로컬 테스트용: 평문 저장 (실제로는 KMS로 암호화)
  created_at TIMESTAMP DEFAULT NOW()
);

-- 테스트용 DEK 생성 (256-bit AES key)
INSERT INTO test_dek_store (key_name, dek)
VALUES
  ('test_ssn_key', gen_random_bytes(32)),
  ('test_cc_key', gen_random_bytes(32))
ON CONFLICT (key_name) DO NOTHING;

\echo '✓ DEK 생성 완료'
SELECT key_name, LENGTH(dek) as key_length_bytes, created_at
FROM test_dek_store;
\echo ''

-- =====================================================
-- 2. 암호화 함수
-- =====================================================

\echo '=== Step 2: 암호화 함수 생성 ==='

CREATE OR REPLACE FUNCTION test_encrypt(p_plaintext TEXT, p_key_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  v_dek BYTEA;
  v_iv BYTEA;
  v_encrypted BYTEA;
BEGIN
  IF p_plaintext IS NULL OR p_plaintext = '' THEN
    RETURN NULL;
  END IF;

  -- DEK 가져오기
  SELECT dek INTO v_dek FROM test_dek_store WHERE key_name = p_key_name;

  IF v_dek IS NULL THEN
    RAISE EXCEPTION 'DEK not found: %', p_key_name;
  END IF;

  -- IV 생성 (16 bytes)
  v_iv := gen_random_bytes(16);

  -- AES-256-CBC 암호화
  v_encrypted := encrypt_iv(
    convert_to(p_plaintext, 'UTF8'),
    v_dek,
    v_iv,
    'aes-cbc/pad:pkcs'
  );

  -- IV + 암호화된 데이터를 Base64로 반환
  RETURN encode(v_iv || v_encrypted, 'base64');
END;
$$;

\echo '✓ 암호화 함수 생성 완료'
\echo ''

-- =====================================================
-- 3. 복호화 함수
-- =====================================================

\echo '=== Step 3: 복호화 함수 생성 ==='

CREATE OR REPLACE FUNCTION test_decrypt(p_encrypted TEXT, p_key_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  v_dek BYTEA;
  v_data BYTEA;
  v_iv BYTEA;
  v_ciphertext BYTEA;
  v_plaintext BYTEA;
BEGIN
  IF p_encrypted IS NULL OR p_encrypted = '' THEN
    RETURN NULL;
  END IF;

  -- DEK 가져오기
  SELECT dek INTO v_dek FROM test_dek_store WHERE key_name = p_key_name;

  IF v_dek IS NULL THEN
    RAISE EXCEPTION 'DEK not found: %', p_key_name;
  END IF;

  -- Base64 디코딩
  v_data := decode(p_encrypted, 'base64');

  -- IV 추출 (처음 16 bytes)
  v_iv := substring(v_data from 1 for 16);

  -- 암호화된 데이터 추출
  v_ciphertext := substring(v_data from 17);

  -- AES-256-CBC 복호화
  v_plaintext := decrypt_iv(
    v_ciphertext,
    v_dek,
    v_iv,
    'aes-cbc/pad:pkcs'
  );

  RETURN convert_from(v_plaintext, 'UTF8');
END;
$$;

\echo '✓ 복호화 함수 생성 완료'
\echo ''

-- =====================================================
-- 4. 테스트 테이블 생성
-- =====================================================

\echo '=== Step 4: 테이블 생성 ==='

CREATE TABLE IF NOT EXISTS test_users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL,
  ssn TEXT,  -- 암호화된 주민번호
  credit_card TEXT,  -- 암호화된 신용카드
  created_at TIMESTAMP DEFAULT NOW()
);

-- 자동 암호화 Trigger
CREATE OR REPLACE FUNCTION test_auto_encrypt_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.ssn IS NOT NULL AND length(NEW.ssn) < 100 THEN
    NEW.ssn := test_encrypt(NEW.ssn, 'test_ssn_key');
  END IF;

  IF NEW.credit_card IS NOT NULL AND length(NEW.credit_card) < 100 THEN
    NEW.credit_card := test_encrypt(NEW.credit_card, 'test_cc_key');
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS test_users_auto_encrypt ON test_users;
CREATE TRIGGER test_users_auto_encrypt
BEFORE INSERT OR UPDATE ON test_users
FOR EACH ROW
EXECUTE FUNCTION test_auto_encrypt_trigger();

-- 복호화 View
CREATE OR REPLACE VIEW test_users_decrypted AS
SELECT
  id,
  username,
  email,
  test_decrypt(ssn, 'test_ssn_key') AS ssn,
  test_decrypt(credit_card, 'test_cc_key') AS credit_card,
  created_at
FROM test_users;

\echo '✓ 테이블 및 View 생성 완료'
\echo ''

-- =====================================================
-- 5. 테스트 데이터 삽입
-- =====================================================

\echo '=== Step 5: 테스트 데이터 삽입 ==='

-- 기존 테스트 데이터 삭제
DELETE FROM test_users;

-- 새 데이터 삽입 (평문으로 입력 → Trigger가 자동 암호화)
INSERT INTO test_users (username, email, ssn, credit_card)
VALUES
  ('john_doe', 'john@example.com', '123-45-6789', '1234-5678-9012-3456'),
  ('jane_smith', 'jane@example.com', '987-65-4321', '9876-5432-1098-7654'),
  ('bob_wilson', 'bob@example.com', '555-12-3456', '5555-6666-7777-8888');

\echo '✓ 3명의 사용자 데이터 삽입 완료'
\echo ''

-- =====================================================
-- 6. 결과 확인
-- =====================================================

\echo '=== Step 6: 결과 확인 ==='
\echo ''

\echo '--- 6-1. 암호화된 데이터 (원본 테이블) ---'
\echo '일반 사용자가 보는 데이터 (암호화된 상태):'
\echo ''

SELECT
  id,
  username,
  LEFT(ssn, 30) || '...' as ssn_encrypted,
  LEFT(credit_card, 30) || '...' as cc_encrypted
FROM test_users
ORDER BY id;

\echo ''
\echo '--- 6-2. 복호화된 데이터 (View) ---'
\echo '권한 있는 사용자가 보는 데이터 (복호화된 상태):'
\echo ''

SELECT
  id,
  username,
  ssn,
  credit_card
FROM test_users_decrypted
ORDER BY id;

\echo ''

-- =====================================================
-- 7. 성능 테스트
-- =====================================================

\echo '=== Step 7: 성능 테스트 ==='
\echo ''

\echo '--- 7-1. 암호화 성능 (100건) ---'
\timing on

DO $$
BEGIN
  FOR i IN 1..100 LOOP
    PERFORM test_encrypt('123-45-6789', 'test_ssn_key');
  END LOOP;
END $$;

\echo ''
\echo '--- 7-2. 복호화 성능 (100건) ---'

DO $$
DECLARE
  v_encrypted TEXT;
  v_decrypted TEXT;
BEGIN
  v_encrypted := test_encrypt('123-45-6789', 'test_ssn_key');

  FOR i IN 1..100 LOOP
    v_decrypted := test_decrypt(v_encrypted, 'test_ssn_key');
  END LOOP;
END $$;

\timing off

\echo ''

-- =====================================================
-- 8. 실제 사용 예시
-- =====================================================

\echo '=== Step 8: 실제 사용 예시 ==='
\echo ''

\echo '--- 8-1. 수동 암호화/복호화 ---'

SELECT
  test_encrypt('새로운 주민번호: 111-22-3333', 'test_ssn_key') as encrypted,
  test_decrypt(
    test_encrypt('새로운 주민번호: 111-22-3333', 'test_ssn_key'),
    'test_ssn_key'
  ) as decrypted;

\echo ''
\echo '--- 8-2. 조건부 조회 (특정 사용자만 복호화) ---'

SELECT
  username,
  CASE
    WHEN username = 'john_doe' THEN test_decrypt(ssn, 'test_ssn_key')
    ELSE '***ENCRYPTED***'
  END as ssn
FROM test_users
ORDER BY id;

\echo ''

-- =====================================================
-- 9. 암호화 강도 확인
-- =====================================================

\echo '=== Step 9: 암호화 강도 확인 ==='
\echo ''

WITH encrypted_data AS (
  SELECT
    username,
    ssn as encrypted_ssn,
    LENGTH(ssn) as encrypted_length,
    LENGTH(decode(ssn, 'base64')) as raw_bytes
  FROM test_users
  LIMIT 1
)
SELECT
  username,
  LEFT(encrypted_ssn, 50) || '...' as sample,
  encrypted_length as base64_length,
  raw_bytes,
  raw_bytes - 16 as data_bytes,
  '16 bytes IV + encrypted data' as structure
FROM encrypted_data;

\echo ''

-- =====================================================
-- 10. 정리
-- =====================================================

\echo '=== Step 10: 테스트 요약 ==='
\echo ''

SELECT
  '총 사용자' as metric,
  COUNT(*)::TEXT as value
FROM test_users
UNION ALL
SELECT
  '암호화된 필드',
  'ssn, credit_card'
UNION ALL
SELECT
  '암호화 알고리즘',
  'AES-256-CBC'
UNION ALL
SELECT
  'DEK 크기',
  '32 bytes (256 bits)'
UNION ALL
SELECT
  'IV 크기',
  '16 bytes (128 bits)';

\echo ''
\echo '=== 테스트 완료! ==='
\echo ''
\echo '다음 명령으로 추가 테스트 가능:'
\echo '  1. SELECT * FROM test_users;                    -- 암호화된 데이터'
\echo '  2. SELECT * FROM test_users_decrypted;          -- 복호화된 데이터'
\echo '  3. SELECT test_encrypt(''테스트'', ''test_ssn_key'');  -- 수동 암호화'
\echo ''
\echo '정리:'
\echo '  DROP TABLE test_users CASCADE;'
\echo '  DROP TABLE test_dek_store;'
\echo '  DROP FUNCTION test_encrypt(TEXT, VARCHAR);'
\echo '  DROP FUNCTION test_decrypt(TEXT, VARCHAR);'

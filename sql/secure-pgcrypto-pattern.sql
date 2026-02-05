-- =====================================================
-- 보안 강화 버전: pgcrypto + DEK 캐싱
-- =====================================================
--
-- 개선사항:
-- 1. UNLOGGED TABLE (백업 불포함)
-- 2. TTL 1분 (노출 시간 최소화)
-- 3. 접근 제어 강화 (SECURITY DEFINER)
-- 4. 감사 로그 강화
-- 5. 런타임 모니터링
--
-- =====================================================

-- pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =====================================================
-- DEK 저장소 (KMS로 암호화된 DEK)
-- =====================================================
CREATE TABLE IF NOT EXISTS dek_store (
  id SERIAL PRIMARY KEY,
  key_name VARCHAR(100) UNIQUE NOT NULL,
  encrypted_dek TEXT NOT NULL,
  algorithm VARCHAR(50) DEFAULT 'aes-256-cbc',
  created_at TIMESTAMP DEFAULT NOW(),
  rotated_at TIMESTAMP,
  active BOOLEAN DEFAULT TRUE,
  kms_key_id VARCHAR(255),
  purpose TEXT
);

-- =====================================================
-- DEK 캐시 (보안 강화)
-- =====================================================

-- UNLOGGED TABLE: 디스크에 기록 안 함, 백업 불포함
CREATE UNLOGGED TABLE IF NOT EXISTS temp_dek_cache (
  session_id TEXT,
  key_name VARCHAR(100),
  plaintext_dek BYTEA,
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  access_count INT DEFAULT 0,
  PRIMARY KEY (session_id, key_name)
);

-- 접근 제어: PUBLIC에서 모든 권한 제거
REVOKE ALL ON temp_dek_cache FROM PUBLIC;

-- 자동 정리 함수
CREATE OR REPLACE FUNCTION cleanup_expired_dek()
RETURNS void
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  DELETE FROM temp_dek_cache WHERE expires_at < NOW();
  RAISE NOTICE 'Expired DEK cache cleaned up';
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- 보안 감사 로그
-- =====================================================
CREATE TABLE IF NOT EXISTS security_audit (
  id SERIAL PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,  -- 'DEK_ACCESS', 'DECRYPT', 'ENCRYPT'
  user_name TEXT NOT NULL,
  session_id TEXT,
  key_name VARCHAR(100),
  ip_address INET,
  success BOOLEAN DEFAULT TRUE,
  error_message TEXT,
  metadata JSONB,
  timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_security_audit_timestamp ON security_audit(timestamp);
CREATE INDEX idx_security_audit_event ON security_audit(event_type, timestamp);
CREATE INDEX idx_security_audit_user ON security_audit(user_name, timestamp);

-- =====================================================
-- DEK 캐시 접근 감사 Trigger
-- =====================================================
CREATE OR REPLACE FUNCTION audit_dek_cache_access()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO security_audit (
      event_type,
      user_name,
      session_id,
      key_name,
      ip_address,
      metadata
    ) VALUES (
      'DEK_CACHE_INSERT',
      current_user,
      NEW.session_id,
      NEW.key_name,
      inet_client_addr(),
      json_build_object('expires_at', NEW.expires_at)::jsonb
    );
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO security_audit (
      event_type,
      user_name,
      session_id,
      key_name,
      metadata
    ) VALUES (
      'DEK_CACHE_DELETE',
      current_user,
      OLD.session_id,
      OLD.key_name,
      json_build_object('access_count', OLD.access_count)::jsonb
    );
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS audit_dek_cache ON temp_dek_cache;
CREATE TRIGGER audit_dek_cache
AFTER INSERT OR DELETE ON temp_dek_cache
FOR EACH ROW
EXECUTE FUNCTION audit_dek_cache_access();

-- =====================================================
-- 평문 DEK 가져오기 (보안 강화)
-- =====================================================
CREATE OR REPLACE FUNCTION get_plaintext_dek(p_key_name VARCHAR)
RETURNS BYTEA
LANGUAGE plpgsql
SECURITY DEFINER  -- 함수 소유자 권한으로 실행
SET search_path = public
AS $$
DECLARE
  v_session_id TEXT;
  v_cached_dek BYTEA;
  v_encrypted_dek TEXT;
  v_lambda_response JSON;
  v_response_body JSON;
  v_plaintext_dek_b64 TEXT;
  v_status_code INT;
BEGIN
  -- 세션 ID
  v_session_id := pg_backend_pid()::TEXT;

  -- 1. 캐시 확인
  SELECT plaintext_dek INTO v_cached_dek
  FROM temp_dek_cache
  WHERE session_id = v_session_id
    AND key_name = p_key_name
    AND expires_at > NOW();

  IF v_cached_dek IS NOT NULL THEN
    -- 캐시 히트 카운트 증가
    UPDATE temp_dek_cache
    SET access_count = access_count + 1
    WHERE session_id = v_session_id AND key_name = p_key_name;

    RETURN v_cached_dek;
  END IF;

  -- 2. 캐시 미스: Lambda로 DEK 복호화
  RAISE NOTICE 'DEK cache miss, calling Lambda for key: %', p_key_name;

  SELECT encrypted_dek INTO v_encrypted_dek
  FROM dek_store
  WHERE key_name = p_key_name AND active = TRUE;

  IF v_encrypted_dek IS NULL THEN
    RAISE EXCEPTION 'DEK not found for key: %', p_key_name;
  END IF;

  -- Lambda 호출 (감사 로그)
  INSERT INTO security_audit (event_type, user_name, key_name, metadata)
  VALUES ('LAMBDA_KMS_CALL', current_user, p_key_name, json_build_object('action', 'decrypt_dek')::jsonb);

  -- Lambda 호출
  SELECT aws_lambda.invoke(
    'arn:aws:lambda:ap-northeast-2:123456789012:function:kms-decrypt',
    v_encrypted_dek,
    'RequestResponse'
  ) INTO v_lambda_response;

  v_status_code := (v_lambda_response->>'StatusCode')::INT;

  IF v_status_code != 200 THEN
    INSERT INTO security_audit (
      event_type, user_name, key_name, success, error_message
    ) VALUES (
      'LAMBDA_KMS_CALL', current_user, p_key_name, FALSE,
      'Lambda returned ' || v_status_code
    );
    RAISE EXCEPTION 'Lambda returned non-200 status: %', v_status_code;
  END IF;

  v_response_body := v_lambda_response->'Payload';

  IF jsonb_typeof(v_response_body::jsonb) = 'string' THEN
    v_response_body := (v_response_body#>>'{}')::JSON;
  END IF;

  IF v_response_body ? 'body' THEN
    v_response_body := (v_response_body->>'body')::JSON;
  END IF;

  v_plaintext_dek_b64 := v_response_body->>'decrypted';
  v_cached_dek := decode(v_plaintext_dek_b64, 'base64');

  -- 3. 캐시 저장 (TTL: 1분)
  INSERT INTO temp_dek_cache (session_id, key_name, plaintext_dek, expires_at)
  VALUES (v_session_id, p_key_name, v_cached_dek, NOW() + INTERVAL '1 minute')
  ON CONFLICT (session_id, key_name)
  DO UPDATE SET plaintext_dek = v_cached_dek, expires_at = NOW() + INTERVAL '1 minute';

  RETURN v_cached_dek;
END;
$$;

-- 일반 사용자는 이 함수 직접 호출 불가
REVOKE ALL ON FUNCTION get_plaintext_dek(VARCHAR) FROM PUBLIC;

-- =====================================================
-- 암호화 함수 (보안 강화)
-- =====================================================
CREATE OR REPLACE FUNCTION encrypt_local(p_plaintext TEXT, p_key_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_dek BYTEA;
  v_iv BYTEA;
  v_encrypted BYTEA;
BEGIN
  IF p_plaintext IS NULL OR p_plaintext = '' THEN
    RETURN NULL;
  END IF;

  -- 이미 암호화된 경우
  IF length(p_plaintext) > 100 THEN
    RETURN p_plaintext;
  END IF;

  -- DEK 가져오기
  v_dek := get_plaintext_dek(p_key_name);

  -- IV 생성
  v_iv := gen_random_bytes(16);

  -- AES-256-CBC 암호화
  v_encrypted := encrypt_iv(
    convert_to(p_plaintext, 'UTF8'),
    v_dek,
    v_iv,
    'aes-cbc/pad:pkcs'
  );

  -- 감사 로그
  INSERT INTO security_audit (event_type, user_name, key_name, success)
  VALUES ('ENCRYPT', current_user, p_key_name, TRUE);

  RETURN encode(v_iv || v_encrypted, 'base64');
EXCEPTION
  WHEN OTHERS THEN
    INSERT INTO security_audit (
      event_type, user_name, key_name, success, error_message
    ) VALUES (
      'ENCRYPT', current_user, p_key_name, FALSE, SQLERRM
    );
    RAISE;
END;
$$;

-- =====================================================
-- 복호화 함수 (보안 강화)
-- =====================================================
CREATE OR REPLACE FUNCTION decrypt_local(p_encrypted TEXT, p_key_name VARCHAR)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_dek BYTEA;
  v_data BYTEA;
  v_iv BYTEA;
  v_ciphertext BYTEA;
  v_plaintext BYTEA;
  current_role TEXT;
BEGIN
  IF p_encrypted IS NULL OR p_encrypted = '' THEN
    RETURN NULL;
  END IF;

  -- 권한 체크
  SELECT current_user INTO current_role;

  IF NOT (current_role = 'admin' OR current_role = 'auditor') THEN
    INSERT INTO security_audit (
      event_type, user_name, key_name, success, error_message
    ) VALUES (
      'DECRYPT_DENIED', current_role, p_key_name, FALSE, 'NO_PERMISSION'
    );
    RETURN '***ENCRYPTED***';
  END IF;

  -- DEK 가져오기
  v_dek := get_plaintext_dek(p_key_name);

  -- Base64 디코딩
  v_data := decode(p_encrypted, 'base64');

  -- IV 추출
  v_iv := substring(v_data from 1 for 16);
  v_ciphertext := substring(v_data from 17);

  -- 복호화
  v_plaintext := decrypt_iv(
    v_ciphertext,
    v_dek,
    v_iv,
    'aes-cbc/pad:pkcs'
  );

  -- 감사 로그
  INSERT INTO security_audit (
    event_type,
    user_name,
    session_id,
    key_name,
    ip_address,
    success
  ) VALUES (
    'DECRYPT',
    current_role,
    pg_backend_pid()::TEXT,
    p_key_name,
    inet_client_addr(),
    TRUE
  );

  RETURN convert_from(v_plaintext, 'UTF8');
EXCEPTION
  WHEN OTHERS THEN
    INSERT INTO security_audit (
      event_type, user_name, key_name, success, error_message
    ) VALUES (
      'DECRYPT', current_role, p_key_name, FALSE, SQLERRM
    );
    RETURN '***DECRYPT_ERROR***';
END;
$$;

-- =====================================================
-- 의심스러운 활동 탐지
-- =====================================================
CREATE OR REPLACE FUNCTION check_suspicious_activity()
RETURNS TABLE(
  session_id TEXT,
  user_name TEXT,
  decrypt_count BIGINT,
  last_activity TIMESTAMP
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    sa.session_id,
    sa.user_name,
    COUNT(*) as decrypt_count,
    MAX(sa.timestamp) as last_activity
  FROM security_audit sa
  WHERE sa.event_type = 'DECRYPT'
    AND sa.timestamp >= NOW() - INTERVAL '5 minutes'
  GROUP BY sa.session_id, sa.user_name
  HAVING COUNT(*) > 100  -- 5분에 100회 이상
  ORDER BY decrypt_count DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- 사용자 테이블 (보안 강화)
-- =====================================================
CREATE TABLE IF NOT EXISTS users_secure (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(100) NOT NULL UNIQUE,
  email VARCHAR(255) NOT NULL UNIQUE,
  ssn TEXT,
  credit_card TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  created_by TEXT DEFAULT current_user
);

-- 자동 암호화 Trigger
CREATE OR REPLACE FUNCTION auto_encrypt_secure_trigger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.ssn IS NOT NULL AND length(NEW.ssn) < 100 THEN
    NEW.ssn := encrypt_local(NEW.ssn, 'users_ssn_key');
  END IF;

  IF NEW.credit_card IS NOT NULL AND length(NEW.credit_card) < 100 THEN
    NEW.credit_card := encrypt_local(NEW.credit_card, 'users_cc_key');
  END IF;

  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_secure_auto_encrypt ON users_secure;
CREATE TRIGGER users_secure_auto_encrypt
BEFORE INSERT OR UPDATE ON users_secure
FOR EACH ROW
EXECUTE FUNCTION auto_encrypt_secure_trigger();

-- 복호화 View
CREATE OR REPLACE VIEW users_secure_decrypted AS
SELECT
  id,
  username,
  email,
  decrypt_local(ssn, 'users_ssn_key') AS ssn,
  decrypt_local(credit_card, 'users_cc_key') AS credit_card,
  created_at,
  updated_at,
  created_by
FROM users_secure;

-- =====================================================
-- DEK 초기화 함수
-- =====================================================
CREATE OR REPLACE FUNCTION initialize_dek(p_key_name VARCHAR, p_purpose TEXT)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_lambda_response JSON;
  v_response_body JSON;
  v_encrypted_dek TEXT;
BEGIN
  SELECT aws_lambda.invoke(
    'arn:aws:lambda:ap-northeast-2:123456789012:function:kms-encrypt',
    json_build_object(
      'action', 'generate_data_key',
      'key_spec', 'AES_256'
    )::TEXT,
    'RequestResponse'
  ) INTO v_lambda_response;

  v_response_body := (v_lambda_response->'Payload'->>'body')::JSON;
  v_encrypted_dek := v_response_body->>'encryptedDataKey';

  INSERT INTO dek_store (key_name, encrypted_dek, purpose, active)
  VALUES (p_key_name, v_encrypted_dek, p_purpose, TRUE)
  ON CONFLICT (key_name) DO NOTHING;

  -- 감사 로그
  INSERT INTO security_audit (event_type, user_name, key_name, metadata)
  VALUES ('DEK_INITIALIZED', current_user, p_key_name, json_build_object('purpose', p_purpose)::jsonb);

  RAISE NOTICE 'DEK initialized for key: %', p_key_name;
END;
$$;

-- =====================================================
-- 권한 설정
-- =====================================================

-- 기본 사용자 권한
GRANT SELECT, INSERT, UPDATE ON users_secure TO app_user;
GRANT SELECT ON users_secure_decrypted TO admin, auditor;

-- 함수 권한 (간접 접근만 허용)
GRANT EXECUTE ON FUNCTION encrypt_local(TEXT, VARCHAR) TO app_user, admin;
GRANT EXECUTE ON FUNCTION decrypt_local(TEXT, VARCHAR) TO admin, auditor;
GRANT EXECUTE ON FUNCTION check_suspicious_activity() TO admin;

-- DEK 관련 테이블은 직접 접근 불가
REVOKE ALL ON dek_store FROM PUBLIC, app_user, admin, auditor;
REVOKE ALL ON temp_dek_cache FROM PUBLIC, app_user, admin, auditor;

-- 감사 로그 조회 권한
GRANT SELECT ON security_audit TO admin, auditor;

-- =====================================================
-- 주기적 정리 작업 (pg_cron 사용 시)
-- =====================================================

-- pg_cron extension 설치 (선택사항)
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

-- 매 5분마다 만료된 캐시 정리
-- SELECT cron.schedule('cleanup-dek-cache', '*/5 * * * *', 'SELECT cleanup_expired_dek();');

-- 매일 오래된 감사 로그 삭제 (90일 이상)
-- SELECT cron.schedule('cleanup-audit-logs', '0 2 * * *',
--   'DELETE FROM security_audit WHERE timestamp < NOW() - INTERVAL ''90 days''');

-- =====================================================
-- 초기 설정 안내
-- =====================================================
DO $$
BEGIN
  RAISE NOTICE '=== Secure pgcrypto Pattern Setup Complete ===';
  RAISE NOTICE '';
  RAISE NOTICE 'Security Features:';
  RAISE NOTICE '  ✓ UNLOGGED TABLE (no backup)';
  RAISE NOTICE '  ✓ TTL: 1 minute';
  RAISE NOTICE '  ✓ SECURITY DEFINER functions';
  RAISE NOTICE '  ✓ Comprehensive audit logging';
  RAISE NOTICE '  ✓ Suspicious activity detection';
  RAISE NOTICE '';
  RAISE NOTICE 'Next steps:';
  RAISE NOTICE '  1. Initialize DEKs:';
  RAISE NOTICE '     SELECT initialize_dek(''users_ssn_key'', ''SSN encryption'');';
  RAISE NOTICE '     SELECT initialize_dek(''users_cc_key'', ''Credit card encryption'');';
  RAISE NOTICE '';
  RAISE NOTICE '  2. Test encryption:';
  RAISE NOTICE '     INSERT INTO users_secure (username, email, ssn)';
  RAISE NOTICE '     VALUES (''test'', ''test@example.com'', ''123-45-6789'');';
  RAISE NOTICE '';
  RAISE NOTICE '  3. Monitor security:';
  RAISE NOTICE '     SELECT * FROM check_suspicious_activity();';
  RAISE NOTICE '     SELECT * FROM security_audit ORDER BY timestamp DESC LIMIT 10;';
END $$;

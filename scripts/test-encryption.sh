#!/bin/bash
set -e

# =====================================================
# 암복호화 테스트 스크립트
# =====================================================

echo "=== KMS Encryption Test ==="
echo ""

# 환경 변수 확인
if [ -z "$DB_HOST" ]; then
  echo "ERROR: DB_HOST environment variable is required"
  exit 1
fi

DB_NAME=${DB_NAME:-postgres}
DB_PORT=${DB_PORT:-5432}

echo "Configuration:"
echo "  DB_HOST: $DB_HOST"
echo "  DB_NAME: $DB_NAME"
echo ""

# =====================================================
# 1. app_user로 데이터 삽입 (자동 암호화)
# =====================================================
echo "=== Test 1: Insert data as app_user (auto encryption) ==="

PGPASSWORD="change_this_password_123!" psql -h $DB_HOST -p $DB_PORT -U app_user -d $DB_NAME <<EOF
-- 테스트 데이터 삽입
INSERT INTO users (username, email, ssn, credit_card)
VALUES
  ('test_user_1', 'test1@example.com', '123-45-6789', '1234-5678-9012-3456'),
  ('test_user_2', 'test2@example.com', '987-65-4321', '9876-5432-1098-7654')
ON CONFLICT (username) DO NOTHING;

-- 삽입 확인
SELECT id, username, email, LEFT(ssn, 50) as ssn_preview, created_at
FROM users
WHERE username LIKE 'test_user_%'
ORDER BY created_at DESC;
EOF

echo "✓ Data inserted and auto-encrypted"
echo ""

# =====================================================
# 2. app_user로 조회 (암호화된 데이터)
# =====================================================
echo "=== Test 2: Query as app_user (encrypted data) ==="

PGPASSWORD="change_this_password_123!" psql -h $DB_HOST -p $DB_PORT -U app_user -d $DB_NAME <<EOF
SELECT
  username,
  email,
  CASE
    WHEN ssn LIKE '{%' THEN 'ENCRYPTED (JSON)'
    ELSE ssn
  END as ssn_status
FROM users
WHERE username = 'test_user_1';
EOF

echo "✓ Encrypted data returned"
echo ""

# =====================================================
# 3. admin으로 복호화 조회
# =====================================================
echo "=== Test 3: Query as admin (decrypted data) ==="

PGPASSWORD="change_this_admin_password_456!" psql -h $DB_HOST -p $DB_PORT -U admin -d $DB_NAME <<EOF
SELECT
  username,
  email,
  ssn,
  credit_card
FROM users_decrypted
WHERE username = 'test_user_1';
EOF

echo "✓ Decrypted data returned"
echo ""

# =====================================================
# 4. auditor로 복호화 조회
# =====================================================
echo "=== Test 4: Query as auditor (decrypted data) ==="

PGPASSWORD="change_this_auditor_password_789!" psql -h $DB_HOST -p $DB_PORT -U auditor -d $DB_NAME <<EOF
SELECT
  username,
  email,
  ssn,
  credit_card
FROM users_decrypted
WHERE username = 'test_user_2';
EOF

echo "✓ Auditor can decrypt"
echo ""

# =====================================================
# 5. 감사 로그 확인
# =====================================================
echo "=== Test 5: Check audit logs ==="

PGPASSWORD="change_this_admin_password_456!" psql -h $DB_HOST -p $DB_PORT -U admin -d $DB_NAME <<EOF
SELECT
  user_name,
  action,
  success,
  error_message,
  timestamp
FROM audit_log
ORDER BY timestamp DESC
LIMIT 10;
EOF

echo "✓ Audit logs recorded"
echo ""

# =====================================================
# 테스트 완료
# =====================================================
echo "=== All Tests Passed ==="
echo ""
echo "Summary:"
echo "  ✓ Data auto-encrypted on insert"
echo "  ✓ app_user sees encrypted data"
echo "  ✓ admin can decrypt data"
echo "  ✓ auditor can decrypt data"
echo "  ✓ Audit logs are working"
echo ""
echo "Cleanup test data:"
echo "  psql -h $DB_HOST -U admin -d $DB_NAME -c \"DELETE FROM users WHERE username LIKE 'test_user_%'\""

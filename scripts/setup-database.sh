#!/bin/bash
set -e

# =====================================================
# PostgreSQL 데이터베이스 설정 스크립트
# =====================================================

echo "=== PostgreSQL Database Setup ==="
echo ""

# 환경 변수 확인
if [ -z "$DB_HOST" ]; then
  echo "ERROR: DB_HOST environment variable is required"
  echo "Example: export DB_HOST='your-rds-endpoint.amazonaws.com'"
  exit 1
fi

if [ -z "$DB_NAME" ]; then
  export DB_NAME="postgres"
  echo "Using default DB_NAME: $DB_NAME"
fi

if [ -z "$DB_USER" ]; then
  export DB_USER="postgres"
  echo "Using default DB_USER: $DB_USER"
fi

if [ -z "$DB_PORT" ]; then
  export DB_PORT="5432"
fi

echo "Configuration:"
echo "  DB_HOST: $DB_HOST"
echo "  DB_PORT: $DB_PORT"
echo "  DB_NAME: $DB_NAME"
echo "  DB_USER: $DB_USER"
echo ""

# psql 확인
if ! command -v psql &> /dev/null; then
  echo "ERROR: psql is not installed"
  exit 1
fi

# 프로젝트 루트로 이동
cd "$(dirname "$0")/.."

# =====================================================
# SQL 스크립트 실행
# =====================================================

echo "=== Step 1: Setting up AWS Lambda extension ==="
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f sql/01-setup-extension.sql
echo "✓ Extension setup complete"
echo ""

echo "=== Step 2: Creating KMS functions ==="
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f sql/02-create-functions.sql
echo "✓ Functions created"
echo ""

echo "=== Step 3: Creating tables and views ==="
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f sql/03-create-tables.sql
echo "✓ Tables and views created"
echo ""

echo "=== Step 4: Creating database users ==="
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f sql/04-create-users.sql
echo "✓ Database users created"
echo ""

# =====================================================
# 설정 완료
# =====================================================
echo "=== Database Setup Complete ==="
echo ""
echo "Created resources:"
echo "  - Functions: encrypt_kms(), decrypt_kms()"
echo "  - Tables: users, audit_log"
echo "  - View: users_decrypted"
echo "  - Users: app_user, admin, auditor"
echo ""
echo "IMPORTANT: Change default passwords in production!"
echo ""
echo "Test the setup:"
echo "  ./scripts/test-encryption.sh"

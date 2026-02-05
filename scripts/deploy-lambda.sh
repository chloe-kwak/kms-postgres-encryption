#!/bin/bash
set -e

# =====================================================
# Lambda 함수 배포 스크립트
# =====================================================

echo "=== KMS Lambda Functions Deployment ==="
echo ""

# 환경 변수 확인
if [ -z "$AWS_REGION" ]; then
  export AWS_REGION="ap-northeast-2"
  echo "Using default AWS_REGION: $AWS_REGION"
fi

if [ -z "$KMS_KEY_ID" ]; then
  echo "ERROR: KMS_KEY_ID environment variable is required"
  echo "Example: export KMS_KEY_ID='arn:aws:kms:ap-northeast-2:123456789012:key/xxx'"
  exit 1
fi

if [ -z "$LAMBDA_ROLE_ARN" ]; then
  echo "ERROR: LAMBDA_ROLE_ARN environment variable is required"
  echo "Example: export LAMBDA_ROLE_ARN='arn:aws:iam::123456789012:role/lambda-kms-role'"
  exit 1
fi

# AWS CLI 확인
if ! command -v aws &> /dev/null; then
  echo "ERROR: AWS CLI is not installed"
  exit 1
fi

echo "Configuration:"
echo "  AWS_REGION: $AWS_REGION"
echo "  KMS_KEY_ID: $KMS_KEY_ID"
echo "  LAMBDA_ROLE_ARN: $LAMBDA_ROLE_ARN"
echo ""

# 프로젝트 루트로 이동
cd "$(dirname "$0")/.."

# =====================================================
# 1. kms-decrypt 함수 빌드 및 배포
# =====================================================
echo "=== Building kms-decrypt function ==="
cd lambda/kms-decrypt

# 의존성 설치
npm install

# TypeScript 빌드
npm run build

# ZIP 패키지 생성
rm -f ../kms-decrypt.zip
zip -r ../kms-decrypt.zip dist node_modules package.json

cd ../..

echo "✓ kms-decrypt built successfully"

# Lambda 함수 생성 또는 업데이트
echo "Deploying kms-decrypt to AWS Lambda..."

if aws lambda get-function --function-name kms-decrypt --region $AWS_REGION &> /dev/null; then
  # 함수가 이미 존재하면 업데이트
  aws lambda update-function-code \
    --function-name kms-decrypt \
    --zip-file fileb://lambda/kms-decrypt.zip \
    --region $AWS_REGION

  aws lambda update-function-configuration \
    --function-name kms-decrypt \
    --environment "Variables={AWS_REGION=$AWS_REGION}" \
    --region $AWS_REGION

  echo "✓ kms-decrypt updated"
else
  # 함수가 없으면 생성
  aws lambda create-function \
    --function-name kms-decrypt \
    --runtime nodejs18.x \
    --role $LAMBDA_ROLE_ARN \
    --handler dist/index.handler \
    --zip-file fileb://lambda/kms-decrypt.zip \
    --environment "Variables={AWS_REGION=$AWS_REGION}" \
    --timeout 30 \
    --memory-size 256 \
    --region $AWS_REGION

  echo "✓ kms-decrypt created"
fi

# =====================================================
# 2. kms-encrypt 함수 빌드 및 배포
# =====================================================
echo ""
echo "=== Building kms-encrypt function ==="
cd lambda/kms-encrypt

# 의존성 설치
npm install

# TypeScript 빌드
npm run build

# ZIP 패키지 생성
rm -f ../kms-encrypt.zip
zip -r ../kms-encrypt.zip dist node_modules package.json

cd ../..

echo "✓ kms-encrypt built successfully"

# Lambda 함수 생성 또는 업데이트
echo "Deploying kms-encrypt to AWS Lambda..."

if aws lambda get-function --function-name kms-encrypt --region $AWS_REGION &> /dev/null; then
  # 함수가 이미 존재하면 업데이트
  aws lambda update-function-code \
    --function-name kms-encrypt \
    --zip-file fileb://lambda/kms-encrypt.zip \
    --region $AWS_REGION

  aws lambda update-function-configuration \
    --function-name kms-encrypt \
    --environment "Variables={AWS_REGION=$AWS_REGION,KMS_KEY_ID=$KMS_KEY_ID}" \
    --region $AWS_REGION

  echo "✓ kms-encrypt updated"
else
  # 함수가 없으면 생성
  aws lambda create-function \
    --function-name kms-encrypt \
    --runtime nodejs18.x \
    --role $LAMBDA_ROLE_ARN \
    --handler dist/index.handler \
    --zip-file fileb://lambda/kms-encrypt.zip \
    --environment "Variables={AWS_REGION=$AWS_REGION,KMS_KEY_ID=$KMS_KEY_ID}" \
    --timeout 30 \
    --memory-size 256 \
    --region $AWS_REGION

  echo "✓ kms-encrypt created"
fi

# =====================================================
# 배포 완료
# =====================================================
echo ""
echo "=== Lambda Functions Deployed Successfully ==="
echo ""
echo "Function ARNs:"
aws lambda get-function --function-name kms-decrypt --region $AWS_REGION --query 'Configuration.FunctionArn' --output text
aws lambda get-function --function-name kms-encrypt --region $AWS_REGION --query 'Configuration.FunctionArn' --output text
echo ""
echo "Next steps:"
echo "1. Update Lambda ARNs in sql/02-create-functions.sql"
echo "2. Run: ./scripts/setup-database.sh"

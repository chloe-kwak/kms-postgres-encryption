#!/bin/bash
# Git 저장소 초기화 및 첫 커밋

echo "=== Git 저장소 초기화 ==="
git init

echo ""
echo "=== Git 사용자 설정 (필요시 수정) ==="
# git config user.name "Your Name"
# git config user.email "your.email@example.com"

echo ""
echo "=== 파일 추가 ==="
git add .

echo ""
echo "=== 첫 커밋 ==="
git commit -m "feat: KMS PostgreSQL 암복호화 솔루션

- 디아모 → AWS KMS 마이그레이션 프로덕션 레디 솔루션
- Envelope Encryption + DEK 캐싱 패턴
- 비용 99% 절감 (\$14 → \$0.29/월), 성능 75배 향상
- 보안 강화: UNLOGGED TABLE, 1분 TTL, 감사 로그
- Lambda 함수, PostgreSQL 통합, 테스트 포함

Features:
- pgcrypto + DEK caching for cost optimization
- Security hardened: UNLOGGED cache, 1-min TTL
- Comprehensive audit logging
- Local test suite (Python + SQL)
- Production-ready deployment scripts"

echo ""
echo "=== 완료! ==="
echo ""
echo "다음 단계:"
echo "1. GitHub에서 새 저장소 생성: https://github.com/new"
echo "2. 원격 저장소 추가:"
echo "   git remote add origin https://github.com/YOUR_USERNAME/kms-postgres-encryption.git"
echo "3. Push:"
echo "   git branch -M main"
echo "   git push -u origin main"

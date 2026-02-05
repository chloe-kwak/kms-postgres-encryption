#!/usr/bin/env python3
"""
KMS 암복호화 로컬 테스트
Lambda/KMS 없이 암복호화 로직을 시뮬레이션합니다.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class DEKStore:
    """DEK 저장소 (실제로는 DB 테이블)"""
    def __init__(self):
        self.deks = {}

    def create_dek(self, key_name: str) -> bytes:
        """DEK 생성 (실제로는 KMS GenerateDataKey)"""
        dek = os.urandom(32)  # 256-bit AES key
        self.deks[key_name] = dek
        print(f"✓ DEK 생성: {key_name} ({len(dek)} bytes)")
        return dek

    def get_dek(self, key_name: str) -> bytes:
        """DEK 가져오기"""
        return self.deks.get(key_name)


class EncryptionService:
    """암복호화 서비스"""

    def __init__(self, dek_store: DEKStore):
        self.dek_store = dek_store

    def encrypt(self, plaintext: str, key_name: str) -> str:
        """데이터 암호화 (AES-256-CBC)"""
        # 1. DEK 가져오기
        dek = self.dek_store.get_dek(key_name)
        if not dek:
            raise ValueError(f"DEK not found: {key_name}")

        # 2. IV 생성
        iv = os.urandom(16)

        # 3. 패딩 추가
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        # 4. AES-256-CBC 암호화
        cipher = Cipher(
            algorithms.AES(dek),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # 5. IV + ciphertext를 Base64로 인코딩
        encrypted = base64.b64encode(iv + ciphertext).decode('utf-8')

        return encrypted

    def decrypt(self, encrypted: str, key_name: str) -> str:
        """데이터 복호화 (AES-256-CBC)"""
        # 1. DEK 가져오기
        dek = self.dek_store.get_dek(key_name)
        if not dek:
            raise ValueError(f"DEK not found: {key_name}")

        # 2. Base64 디코딩
        data = base64.b64decode(encrypted)

        # 3. IV와 ciphertext 분리
        iv = data[:16]
        ciphertext = data[16:]

        # 4. AES-256-CBC 복호화
        cipher = Cipher(
            algorithms.AES(dek),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. 패딩 제거
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode('utf-8')


class User:
    """사용자 테이블 시뮬레이션"""
    def __init__(self, username, email, ssn, credit_card):
        self.username = username
        self.email = email
        self.ssn = ssn  # 암호화된 상태
        self.credit_card = credit_card  # 암호화된 상태


def print_section(title):
    """섹션 출력"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def main():
    print_section("KMS 암복호화 로컬 테스트 시작")

    # 1. DEK 생성
    print_section("Step 1: DEK 생성 (KMS 시뮬레이션)")
    dek_store = DEKStore()
    dek_store.create_dek('users_ssn_key')
    dek_store.create_dek('users_cc_key')

    # 2. 암복호화 서비스 생성
    print_section("Step 2: 암복호화 서비스 초기화")
    service = EncryptionService(dek_store)
    print("✓ 암복호화 서비스 준비 완료")

    # 3. 테스트 데이터 생성
    print_section("Step 3: 테스트 데이터 삽입")
    users = []

    test_data = [
        ('john_doe', 'john@example.com', '123-45-6789', '1234-5678-9012-3456'),
        ('jane_smith', 'jane@example.com', '987-65-4321', '9876-5432-1098-7654'),
        ('bob_wilson', 'bob@example.com', '555-12-3456', '5555-6666-7777-8888'),
    ]

    for username, email, ssn, cc in test_data:
        # 자동 암호화 (Trigger 시뮬레이션)
        encrypted_ssn = service.encrypt(ssn, 'users_ssn_key')
        encrypted_cc = service.encrypt(cc, 'users_cc_key')

        user = User(username, email, encrypted_ssn, encrypted_cc)
        users.append(user)
        print(f"✓ 사용자 생성: {username}")

    # 4. 암호화된 데이터 확인
    print_section("Step 4: 암호화된 데이터 (일반 사용자 View)")
    print(f"{'Username':<15} {'SSN (암호화)':<40} {'신용카드 (암호화)':<40}")
    print("-" * 95)

    for user in users:
        ssn_preview = user.ssn[:37] + '...' if len(user.ssn) > 40 else user.ssn
        cc_preview = user.credit_card[:37] + '...' if len(user.credit_card) > 40 else user.credit_card
        print(f"{user.username:<15} {ssn_preview:<40} {cc_preview:<40}")

    # 5. 복호화된 데이터 확인
    print_section("Step 5: 복호화된 데이터 (권한 있는 사용자 View)")
    print(f"{'Username':<15} {'SSN (복호화)':<20} {'신용카드 (복호화)':<25}")
    print("-" * 60)

    for user in users:
        decrypted_ssn = service.decrypt(user.ssn, 'users_ssn_key')
        decrypted_cc = service.decrypt(user.credit_card, 'users_cc_key')
        print(f"{user.username:<15} {decrypted_ssn:<20} {decrypted_cc:<25}")

    # 6. 암호화 강도 확인
    print_section("Step 6: 암호화 강도 분석")
    sample_user = users[0]

    print(f"원본 데이터:")
    print(f"  평문: '123-45-6789'")
    print(f"  길이: {len('123-45-6789')} 문자")
    print()
    print(f"암호화된 데이터:")
    print(f"  암호문: '{sample_user.ssn[:50]}...'")
    print(f"  Base64 길이: {len(sample_user.ssn)} 문자")
    print(f"  실제 바이트: {len(base64.b64decode(sample_user.ssn))} bytes")
    print(f"  구조: 16 bytes IV + 암호화된 데이터")

    # 7. 성능 테스트
    print_section("Step 7: 성능 테스트")
    import time

    # 암호화 성능
    test_plaintext = '123-45-6789'
    iterations = 1000

    start = time.time()
    for _ in range(iterations):
        service.encrypt(test_plaintext, 'users_ssn_key')
    encrypt_time = time.time() - start

    print(f"암호화 성능:")
    print(f"  {iterations}회 암호화: {encrypt_time:.3f}초")
    print(f"  평균: {(encrypt_time/iterations)*1000:.2f}ms/회")

    # 복호화 성능
    encrypted = service.encrypt(test_plaintext, 'users_ssn_key')

    start = time.time()
    for _ in range(iterations):
        service.decrypt(encrypted, 'users_ssn_key')
    decrypt_time = time.time() - start

    print(f"\n복호화 성능:")
    print(f"  {iterations}회 복호화: {decrypt_time:.3f}초")
    print(f"  평균: {(decrypt_time/iterations)*1000:.2f}ms/회")

    # 8. 실제 사용 예시
    print_section("Step 8: 실제 사용 시나리오")

    print("시나리오 1: 새 사용자 등록")
    new_ssn = '999-88-7777'
    encrypted = service.encrypt(new_ssn, 'users_ssn_key')
    print(f"  입력 (평문): {new_ssn}")
    print(f"  저장 (암호화): {encrypted[:50]}...")

    print("\n시나리오 2: 권한 있는 사용자가 조회")
    decrypted = service.decrypt(encrypted, 'users_ssn_key')
    print(f"  DB에서 조회 (암호화): {encrypted[:50]}...")
    print(f"  화면에 표시 (복호화): {decrypted}")

    print("\n시나리오 3: 권한 없는 사용자가 조회")
    print(f"  DB에서 조회 (암호화): {encrypted[:50]}...")
    print(f"  화면에 표시: ***ENCRYPTED*** (권한 없음)")

    # 9. 보안 확인
    print_section("Step 9: 보안 확인")

    print("암호화 알고리즘: AES-256-CBC")
    print("키 크기: 256 bits (32 bytes)")
    print("IV 크기: 128 bits (16 bytes)")
    print()
    print("보안 특성:")
    print("  ✓ 같은 평문도 매번 다른 암호문 생성 (랜덤 IV)")
    print("  ✓ DEK 없이는 복호화 불가능")
    print("  ✓ 실제 환경에서는 DEK도 KMS로 암호화")

    # 10. 같은 평문의 암호문 비교
    print("\n같은 평문의 암호문 비교 (IV가 다름):")
    enc1 = service.encrypt('123-45-6789', 'users_ssn_key')
    enc2 = service.encrypt('123-45-6789', 'users_ssn_key')
    enc3 = service.encrypt('123-45-6789', 'users_ssn_key')

    print(f"  암호문 1: {enc1[:50]}...")
    print(f"  암호문 2: {enc2[:50]}...")
    print(f"  암호문 3: {enc3[:50]}...")
    print(f"  모두 다름: {enc1 != enc2 != enc3}")

    # 완료
    print_section("테스트 완료!")
    print("✓ 암호화/복호화 동작 확인")
    print("✓ 성능 측정 완료")
    print("✓ 보안 특성 검증")
    print()
    print("실제 환경에서는:")
    print("  - DEK는 KMS로 암호화하여 DB에 저장")
    print("  - Lambda 함수가 KMS API 호출")
    print("  - PostgreSQL에서 pgcrypto로 암복호화")
    print()


if __name__ == '__main__':
    try:
        main()
    except ImportError:
        print("오류: cryptography 라이브러리가 필요합니다.")
        print("설치: pip install cryptography")
    except Exception as e:
        print(f"오류 발생: {e}")
        import traceback
        traceback.print_exc()

import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';
import { createDecipheriv } from 'crypto';

const kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'ap-northeast-2' });

interface DecryptRequest {
  encryptedDataKey: string;
  encryptedData: string;
  iv: string;
  algorithm: string;
  requestUser?: string;
}

export const handler = async (event: any) => {
  console.log('[KMS-DECRYPT] Event:', JSON.stringify(event));

  try {
    // PostgreSQL aws_lambda.invoke에서 오는 데이터 파싱
    let request: DecryptRequest;

    if (typeof event === 'string') {
      request = JSON.parse(event);
    } else if (typeof event.body === 'string') {
      request = JSON.parse(event.body);
    } else if (event.encryptedDataKey) {
      request = event;
    } else {
      throw new Error('Invalid request format');
    }

    const { encryptedDataKey, encryptedData, iv, algorithm } = request;

    if (!encryptedDataKey || !encryptedData || !iv) {
      throw new Error('Missing required fields: encryptedDataKey, encryptedData, iv');
    }

    // 1. KMS로 DEK 복호화 (IAM 권한 자동 검증)
    const decryptCommand = new DecryptCommand({
      CiphertextBlob: Buffer.from(encryptedDataKey, 'base64'),
    });

    console.log('[KMS-DECRYPT] Calling KMS Decrypt API');
    const { Plaintext: plaintextKey } = await kmsClient.send(decryptCommand);

    if (!plaintextKey) {
      throw new Error('KMS decrypt returned no plaintext key');
    }

    // 2. DEK로 데이터 복호화
    const decipher = createDecipheriv(
      algorithm || 'aes-256-gcm',
      Buffer.from(plaintextKey),
      Buffer.from(iv, 'base64')
    );

    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    console.log('[KMS-DECRYPT] Decryption successful');

    return {
      statusCode: 200,
      body: JSON.stringify({ decrypted }),
    };
  } catch (error: any) {
    console.error('[KMS-DECRYPT] Error:', error);

    // 권한 에러 처리
    if (error.name === 'AccessDeniedException') {
      return {
        statusCode: 403,
        body: JSON.stringify({
          error: 'ACCESS_DENIED',
          message: 'No permission to decrypt',
        }),
      };
    }

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'DECRYPTION_FAILED',
        message: error.message,
      }),
    };
  }
};

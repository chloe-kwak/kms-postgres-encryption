import { KMSClient, GenerateDataKeyCommand } from '@aws-sdk/client-kms';
import { createCipheriv, randomBytes } from 'crypto';

const kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'ap-northeast-2' });
const KMS_KEY_ID = process.env.KMS_KEY_ID;

if (!KMS_KEY_ID) {
  throw new Error('KMS_KEY_ID environment variable is required');
}

export const handler = async (event: any) => {
  console.log('[KMS-ENCRYPT] Event:', JSON.stringify(event));

  try {
    // PostgreSQL aws_lambda.invoke에서 오는 데이터 파싱
    let plaintext: string;

    if (typeof event === 'string') {
      const parsed = JSON.parse(event);
      plaintext = parsed.plaintext;
    } else if (typeof event.body === 'string') {
      const parsed = JSON.parse(event.body);
      plaintext = parsed.plaintext;
    } else if (event.plaintext) {
      plaintext = event.plaintext;
    } else {
      throw new Error('Plaintext is required');
    }

    if (!plaintext) {
      throw new Error('Plaintext cannot be empty');
    }

    // 1. KMS에서 DEK 생성
    const generateKeyCommand = new GenerateDataKeyCommand({
      KeyId: KMS_KEY_ID,
      KeySpec: 'AES_256',
    });

    console.log('[KMS-ENCRYPT] Generating data key from KMS');
    const { Plaintext: plaintextKey, CiphertextBlob: encryptedKey } =
      await kmsClient.send(generateKeyCommand);

    if (!plaintextKey || !encryptedKey) {
      throw new Error('Failed to generate data key');
    }

    // 2. DEK로 데이터 암호화
    const algorithm = 'aes-256-gcm';
    const iv = randomBytes(16);
    const cipher = createCipheriv(algorithm, Buffer.from(plaintextKey), iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const result = {
      encryptedDataKey: Buffer.from(encryptedKey).toString('base64'),
      encryptedData: encrypted,
      iv: iv.toString('base64'),
      algorithm,
    };

    console.log('[KMS-ENCRYPT] Encryption successful');

    return {
      statusCode: 200,
      body: JSON.stringify(result),
    };
  } catch (error: any) {
    console.error('[KMS-ENCRYPT] Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'ENCRYPTION_FAILED',
        message: error.message,
      }),
    };
  }
};

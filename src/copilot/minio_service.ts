import * as Minio from 'minio';

const minioEndPoint = process.env.MINIO_ENDPOINT || 'localhost';
const minioPort = parseInt(process.env.MINIO_PORT || '9000');
const minioAccessKey = process.env.MINIO_ACCESS_KEY || 'minioadmin';
const minioSecretKey = process.env.MINIO_SECRET_KEY || 'minioadmin';

// Initialize the S3/MinIO client
export const minioClient = new Minio.Client({
  endPoint: minioEndPoint,
  port: minioPort,
  useSSL: false,
  accessKey: minioAccessKey,
  secretKey: minioSecretKey,
});

export const BUCKET_NAME = 'playbooks';

export async function initMinio() {
  console.log("[MinIO Startup] Connecting to MinIO storage client...");
  try {
    const exists = await minioClient.bucketExists(BUCKET_NAME).catch(() => false);
    if (!exists) {
      await minioClient.makeBucket(BUCKET_NAME, 'us-east-1');
      console.log(`[MinIO Startup] Created MinIO bucket: ${BUCKET_NAME}`);
    } else {
      console.log(`[MinIO Startup] MinIO bucket '${BUCKET_NAME}' ready.`);
    }
  } catch (err: any) {
    console.warn("[MinIO Warning] MinIO initialization failed. Storage operations will degrade. Error:", err.message);
  }
}

// Upload document buffer to storage bucket
export async function uploadToMinio(filename: string, dataBuffer: Buffer, size: number): Promise<string> {
  const objectName = `${Date.now()}_${filename}`;
  await minioClient.putObject(BUCKET_NAME, objectName, dataBuffer, size);
  return objectName;
}

// Get presigned S3 download/view URL
export async function getPresignedUrl(objectName: string): Promise<string> {
  return await minioClient.presignedGetObject(BUCKET_NAME, objectName, 3600); // 1 hour expiration
}
export default minioClient;

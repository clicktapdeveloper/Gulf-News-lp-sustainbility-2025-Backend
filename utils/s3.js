import { S3Client, PutObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';

/**
 * AWS S3 Configuration Object
 * @typedef {Object} S3Config
 * @property {string} region - AWS region
 * @property {string} accessKeyId - AWS access key ID
 * @property {string} secretAccessKey - AWS secret access key
 * @property {string} bucketName - S3 bucket name
 */

/**
 * File Upload Result Object
 * @typedef {Object} UploadResult
 * @property {string} url - File URL
 * @property {string} key - S3 object key
 * @property {string} originalName - Original file name
 * @property {string} mimetype - File MIME type
 * @property {number} size - File size in bytes
 * @property {string} uploadedAt - Upload timestamp
 */

function getS3Config() {
  const region = process.env.AWS_REGION || 'us-east-1';
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID || '';
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY || '';
  const bucketName = process.env.S3_BUCKET_NAME || '';

  // Debug logging to help identify configuration issues
  console.log('S3 Config Debug:', {
    region,
    bucketName: bucketName ? `${bucketName.substring(0, 4)}...` : 'NOT_SET',
    accessKeyId: accessKeyId ? `${accessKeyId.substring(0, 4)}...` : 'NOT_SET',
    secretAccessKey: secretAccessKey ? 'SET' : 'NOT_SET'
  });

  // Validate required configuration
  if (!accessKeyId) {
    throw new Error('AWS_ACCESS_KEY_ID is required');
  }
  if (!secretAccessKey) {
    throw new Error('AWS_SECRET_ACCESS_KEY is required');
  }
  if (!bucketName) {
    throw new Error('S3_BUCKET_NAME is required');
  }

  return {
    region,
    accessKeyId,
    secretAccessKey,
    bucketName
  };
}

class S3Service {
  /**
   * Create a new S3 service instance
   * @param {S3Config} config - Configuration object
   */
  constructor(config) {
    this.config = config;
    this.s3Client = new S3Client({
      region: config.region,
      credentials: {
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
      },
    });
  }

  /**
   * Upload a file to S3
   * @param {Buffer} fileBuffer - File buffer
   * @param {string} fileName - Original file name
   * @param {string} mimetype - File MIME type
   * @param {string} [folder] - Folder path in S3
   * @returns {Promise<UploadResult>} Upload result
   */
  async uploadFile(fileBuffer, fileName, mimetype, folder = 'uploads') {
    try {
      const timestamp = Date.now();
      const ext = fileName.split('.').pop();
      const baseName = fileName.replace(/\.[^/.]+$/, '');
      const cleanBase = baseName.replace(/\s+/g, '_');
      
      // Determine folder based on file type
      let uploadFolder = folder;
      if (mimetype === 'application/pdf' || fileName.toLowerCase().endsWith('.pdf')) {
        uploadFolder = 'uploads/reports';
      }
      
      const fileKey = `${uploadFolder}/${timestamp}-${cleanBase}.${ext}`;
      
      const uploadCommand = new PutObjectCommand({
        Bucket: this.config.bucketName,
        Key: fileKey,
        Body: fileBuffer,
        ContentType: mimetype,
        Metadata: {
          originalName: fileName,
          uploadedAt: new Date().toISOString(),
        }
      });
      
      console.log('Uploading to S3:', {
        Bucket: this.config.bucketName,
        Key: fileKey,
        ContentType: mimetype,
        Size: fileBuffer.length
      });
      
      await this.s3Client.send(uploadCommand);
      
      const fileUrl = `https://${this.config.bucketName}.s3.${this.config.region}.amazonaws.com/${fileKey}`;
      
      return {
        url: fileUrl,
        key: fileKey,
        originalName: fileName,
        mimetype: mimetype,
        size: fileBuffer.length,
        uploadedAt: new Date().toISOString()
      };
      
    } catch (error) {
      console.error('S3 Upload Error:', error);
      throw new Error(`Failed to upload file to S3: ${error.message}`);
    }
  }

  /**
   * Delete a file from S3
   * @param {string} fileKey - S3 object key
   * @returns {Promise<boolean>} Success status
   */
  async deleteFile(fileKey) {
    try {
      const deleteCommand = new DeleteObjectCommand({
        Bucket: this.config.bucketName,
        Key: fileKey
      });
      
      await this.s3Client.send(deleteCommand);
      console.log('File deleted from S3:', fileKey);
      return true;
      
    } catch (error) {
      console.error('S3 Delete Error:', error);
      throw new Error(`Failed to delete file from S3: ${error.message}`);
    }
  }

  /**
   * List files in S3 bucket
   * @param {string} [prefix] - Prefix to filter files
   * @returns {Promise<Array>} List of files
   */
  async listFiles(prefix = 'uploads/') {
    try {
      const listCommand = new ListObjectsV2Command({
        Bucket: this.config.bucketName,
        Prefix: prefix
      });
      
      const response = await this.s3Client.send(listCommand);
      return response.Contents || [];
      
    } catch (error) {
      console.error('S3 List Error:', error);
      throw new Error(`Failed to list files from S3: ${error.message}`);
    }
  }

  /**
   * Generate a presigned URL for file access
   * @param {string} fileKey - S3 object key
   * @param {number} [expiresIn] - Expiration time in seconds (default: 3600)
   * @returns {Promise<string>} Presigned URL
   */
  async getPresignedUrl(fileKey, expiresIn = 3600) {
    try {
      const { getSignedUrl } = await import('@aws-sdk/s3-request-presigner');
      const { GetObjectCommand } = await import('@aws-sdk/client-s3');
      
      const command = new GetObjectCommand({
        Bucket: this.config.bucketName,
        Key: fileKey
      });
      
      const presignedUrl = await getSignedUrl(this.s3Client, command, { expiresIn });
      return presignedUrl;
      
    } catch (error) {
      console.error('S3 Presigned URL Error:', error);
      throw new Error(`Failed to generate presigned URL: ${error.message}`);
    }
  }
}

/**
 * Create S3 service instance
 * @returns {S3Service} S3 service instance
 */
export function createS3Service() {
  const config = getS3Config();
  return new S3Service(config);
}

/**
 * Upload file to S3 (convenience function)
 * @param {Buffer} fileBuffer - File buffer
 * @param {string} fileName - Original file name
 * @param {string} mimetype - File MIME type
 * @param {string} [folder] - Folder path in S3
 * @returns {Promise<UploadResult>} Upload result
 */
export async function uploadFileToS3(fileBuffer, fileName, mimetype, folder) {
  const s3Service = createS3Service();
  return await s3Service.uploadFile(fileBuffer, fileName, mimetype, folder);
}

/**
 * Delete file from S3 (convenience function)
 * @param {string} fileKey - S3 object key
 * @returns {Promise<boolean>} Success status
 */
export async function deleteFileFromS3(fileKey) {
  const s3Service = createS3Service();
  return await s3Service.deleteFile(fileKey);
}

/**
 * List files in S3 (convenience function)
 * @param {string} [prefix] - Prefix to filter files
 * @returns {Promise<Array>} List of files
 */
export async function listFilesInS3(prefix) {
  const s3Service = createS3Service();
  return await s3Service.listFiles(prefix);
}

export { S3Service };
export default S3Service;

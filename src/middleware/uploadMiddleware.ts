// config/upload.ts - Production Configuration
import multer from 'multer'; // Import multer for file upload handling
import { S3Client } from '@aws-sdk/client-s3'; // Import AWS S3 client
import multerS3 from 'multer-s3'; // Import S3 storage engine for multer
import { v4 as uuidv4 } from 'uuid'; // Import UUID for unique filenames
import path from 'path'; // Import path for file extension handling
import { config } from '../config/config.js';

// AWS S3 Configuration
// In production, use IAM role credentials (no explicit credentials needed)
// In development, use explicit credentials from environment variables
const s3Config: {
  region: string;
  maxAttempts: number;
  retryMode: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
  };
} = {
  region: config.AWS_REGION!,
  maxAttempts: 3,
  retryMode: 'standard',
};

// Only add explicit credentials in development or when credentials are provided
if (config.NODE_ENV === 'development' && config.AWS_ACCESS_KEY_ID && config.AWS_SECRET_ACCESS_KEY) {
  s3Config.credentials = {
    accessKeyId: config.AWS_ACCESS_KEY_ID,
    secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
  };
  console.log('🔑 Using explicit AWS credentials for development');
} else {
  console.log('🔐 Using IAM role credentials for production');
}

const s3 = new S3Client(s3Config);

const prodStorage = multerS3({
  s3,
  bucket: config.S3_BUCKET_NAME!,
  contentType: multerS3.AUTO_CONTENT_TYPE,
  metadata: (req, file, cb) => {
    // Add metadata for better management
    cb(null, {
      fieldName: file.fieldname, // Form field name
      originalName: file.originalname, // Original filename
      uploadedBy: 'user-signup-system',
      uploadTime: new Date().toISOString(),
    });
  },
  key: (req, file, cb) => {
    const extension = path.extname(file.originalname); // Get file extension
    const fileName = `profile-pictures/${uuidv4()}${extension}`; // Create unique path

    console.log('📁 S3 Upload Key:', fileName); // Log the S3 key
    cb(null, fileName); // Set the S3 object key
  },
});

// Production file filter - more strict
const productionFileFilter = (
  req: Express.Request,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) => {
  // Only allow specific image types for security
  const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];

  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true); // Accept file
  } else {
    cb(
      // Reject with detailed error
      new Error(
        `Unsupported file type: ${file.mimetype}. Allowed types: ${allowedMimes.join(', ')}`
      )
    );
  }
};

export const upload = multer({
  storage: prodStorage, // Use S3 storage
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit (more restrictive)
  },
  fileFilter: productionFileFilter, // Use strict production file filter
});

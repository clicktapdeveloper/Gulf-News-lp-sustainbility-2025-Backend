# AWS S3 PDF Upload Implementation Guide

This guide provides a complete implementation for uploading PDF files to AWS S3 using Node.js, Express, and Multer. This implementation is based on a production-ready car listing application.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Dependencies Installation](#dependencies-installation)
4. [AWS S3 Configuration](#aws-s3-configuration)
5. [Backend Implementation](#backend-implementation)
6. [Frontend Integration](#frontend-integration)
7. [Testing](#testing)
8. [Security Considerations](#security-considerations)
9. [Error Handling](#error-handling)
10. [Production Deployment](#production-deployment)

## Prerequisites

- Node.js (v14 or higher)
- AWS Account with S3 access
- Basic knowledge of Express.js and Multer

## Environment Setup

Create a `.env` file in your project root with the following variables:

```env
# AWS Configuration
AWS_REGION=your-aws-region
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
S3_BUCKET_NAME=your-bucket-name

# Server Configuration
PORT=8080
NODE_ENV=development
BASE_URL=http://localhost:8080

# Database (if using MongoDB)
MONGODB_URI=your-mongodb-connection-string

# JWT Secret (if using authentication)
JWT_SECRET=your-jwt-secret-key
```

## Dependencies Installation

Install the required packages:

```bash
npm install express multer @aws-sdk/client-s3 @aws-sdk/s3-request-presigner cors cookie-parser dotenv
```

For development:
```bash
npm install --save-dev nodemon
```

## AWS S3 Configuration

### 1. Create S3 Bucket

1. Log into AWS Console
2. Navigate to S3 service
3. Create a new bucket with a unique name
4. Configure bucket settings:
   - **Region**: Choose your preferred region
   - **Public Access**: Configure based on your needs
   - **Versioning**: Enable if needed
   - **Server-side encryption**: Enable for security

### 2. Configure CORS Policy

Add the following CORS policy to your S3 bucket:

```json
[
    {
        "AllowedHeaders": ["*"],
        "AllowedMethods": ["GET", "PUT", "POST", "DELETE"],
        "AllowedOrigins": ["*"],
        "ExposeHeaders": []
    }
]
```

### 3. Create IAM User

1. Create a new IAM user with programmatic access
2. Attach the following policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name"
        }
    ]
}
```

## Backend Implementation

### 1. Main Server File (index.js)

```javascript
require("dotenv").config();
const fs = require("fs");
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const cookieParser = require('cookie-parser');
const path = require("path");
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const app = express();

// CORS Configuration
const allowedOrigins = [
    'http://localhost:3000', 
    'http://localhost:4000', 
    'https://yourdomain.com'
];

app.use(cors({
    origin: function (origin, callback) {
        if (allowedOrigins.includes(origin) || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

// Environment variables
const PORT = process.env.PORT || 8080;

// AWS S3 client configuration
const s3 = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

// Multer configuration for memory storage
const storage = multer.memoryStorage();
const upload = multer({ 
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
    },
    fileFilter: (req, file, cb) => {
        // Allow PDF files
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF files are allowed'), false);
        }
    }
}).any();

// S3 Upload Endpoint
app.post("/api/upload", upload, async (req, res) => {
    console.log("=== UPLOAD REQUEST RECEIVED ===");
    console.log("Request files:", req.files);
    console.log("Request body:", req.body);
    
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ 
            error: "No file uploaded", 
            message: "Please select a PDF file to upload"
        });
    }

    const uploadedFiles = [];

    try {
        // Process all uploaded files
        for (const file of req.files) {
            const timestamp = Date.now();
            const ext = path.extname(file.originalname);
            const baseName = path.basename(file.originalname, ext);
            const cleanBase = baseName.replace(/\s+/g, '_');
            
            // Determine folder based on file type
            let folder = 'uploads';
            if (file.mimetype === 'application/pdf' || ext.toLowerCase() === '.pdf') {
                folder = 'uploads/reports';
            }
            
            const fileKey = `${folder}/${timestamp}-${cleanBase}${ext}`;
            
            const uploadCommand = new PutObjectCommand({
                Bucket: process.env.S3_BUCKET_NAME,
                Key: fileKey,
                Body: file.buffer,
                ContentType: file.mimetype,
                Metadata: {
                    originalName: file.originalname,
                    uploadedAt: new Date().toISOString(),
                }
            });
            
            console.log('Uploading to S3:', {
                Bucket: process.env.S3_BUCKET_NAME,
                Key: fileKey,
                ContentType: file.mimetype
            });
            
            await s3.send(uploadCommand);
            const fileUrl = `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${fileKey}`;
            
            const uploadedMeta = {
                type: file.fieldname,
                url: fileUrl,
                originalname: file.originalname,
                fieldname: file.fieldname,
                mimetype: file.mimetype,
                size: file.size,
                uploadedAt: new Date().toISOString()
            };
            uploadedFiles.push(uploadedMeta);
        }

        console.log("Uploaded file(s):", uploadedFiles);
        res.json({ 
            success: true,
            uploaded: uploadedFiles,
            message: "PDF uploaded successfully"
        });

    } catch (err) {
        console.error('Upload error:', err.name, err.message, err.stack);
        res.status(500).json({ 
            error: 'Upload failed', 
            details: err.message 
        });
    }
});

// Health check endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'S3 PDF Upload Service', 
        status: 'running',
        timestamp: new Date().toISOString()
    });
});

app.listen(PORT, () => {
    console.log(`Server running on ${process.env.BASE_URL || `http://localhost:${PORT}`} in ${process.env.NODE_ENV} mode`);
});
```

### 2. Package.json Scripts

```json
{
    "scripts": {
        "start": "node index.js",
        "dev": "nodemon index.js",
        "test": "echo \"Error: no test specified\" && exit 1"
    }
}
```

## Frontend Integration

### 1. HTML Form

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Upload</title>
</head>
<body>
    <form id="pdfUploadForm" enctype="multipart/form-data">
        <div>
            <label for="pdfFile">Select PDF File:</label>
            <input type="file" id="pdfFile" name="pdfFile" accept=".pdf" required>
        </div>
        <div>
            <label for="listingId">Listing ID (optional):</label>
            <input type="text" id="listingId" name="listingId">
        </div>
        <button type="submit">Upload PDF</button>
    </form>

    <div id="result"></div>

    <script>
        document.getElementById('pdfUploadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData();
            const fileInput = document.getElementById('pdfFile');
            const listingId = document.getElementById('listingId').value;
            
            if (fileInput.files.length === 0) {
                alert('Please select a PDF file');
                return;
            }
            
            formData.append('pdfFile', fileInput.files[0]);
            if (listingId) {
                formData.append('listingId', listingId);
            }
            
            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('result').innerHTML = `
                        <h3>Upload Successful!</h3>
                        <p><strong>File:</strong> ${result.uploaded[0].originalname}</p>
                        <p><strong>URL:</strong> <a href="${result.uploaded[0].url}" target="_blank">${result.uploaded[0].url}</a></p>
                        <p><strong>Size:</strong> ${(result.uploaded[0].size / 1024).toFixed(2)} KB</p>
                    `;
                } else {
                    document.getElementById('result').innerHTML = `
                        <h3>Upload Failed</h3>
                        <p>${result.error}</p>
                    `;
                }
            } catch (error) {
                document.getElementById('result').innerHTML = `
                    <h3>Error</h3>
                    <p>${error.message}</p>
                `;
            }
        });
    </script>
</body>
</html>
```

### 2. React Component

```jsx
import React, { useState } from 'react';

const PDFUpload = () => {
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [result, setResult] = useState(null);

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        
        if (!file) {
            alert('Please select a PDF file');
            return;
        }

        setUploading(true);
        const formData = new FormData();
        formData.append('pdfFile', file);

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            setResult(data);
        } catch (error) {
            setResult({ error: error.message });
        } finally {
            setUploading(false);
        }
    };

    return (
        <div>
            <form onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="pdfFile">Select PDF File:</label>
                    <input
                        type="file"
                        id="pdfFile"
                        accept=".pdf"
                        onChange={handleFileChange}
                        required
                    />
                </div>
                <button type="submit" disabled={uploading}>
                    {uploading ? 'Uploading...' : 'Upload PDF'}
                </button>
            </form>

            {result && (
                <div>
                    {result.success ? (
                        <div>
                            <h3>Upload Successful!</h3>
                            <p><strong>File:</strong> {result.uploaded[0].originalname}</p>
                            <p><strong>URL:</strong> <a href={result.uploaded[0].url} target="_blank" rel="noopener noreferrer">{result.uploaded[0].url}</a></p>
                        </div>
                    ) : (
                        <div>
                            <h3>Upload Failed</h3>
                            <p>{result.error}</p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default PDFUpload;
```

## Testing

### 1. Using cURL

```bash
curl -X POST \
  http://localhost:8080/api/upload \
  -H 'Content-Type: multipart/form-data' \
  -F 'pdfFile=@/path/to/your/file.pdf'
```

### 2. Using Postman

1. Set method to POST
2. URL: `http://localhost:8080/api/upload`
3. Body → form-data
4. Key: `pdfFile`, Type: File, Value: Select your PDF file
5. Send request

### 3. Test Script

```javascript
const fs = require('fs');
const FormData = require('form-data');
const fetch = require('node-fetch');

async function testUpload() {
    const form = new FormData();
    form.append('pdfFile', fs.createReadStream('./test.pdf'));
    
    try {
        const response = await fetch('http://localhost:8080/api/upload', {
            method: 'POST',
            body: form
        });
        
        const result = await response.json();
        console.log('Upload result:', result);
    } catch (error) {
        console.error('Error:', error);
    }
}

testUpload();
```

## Security Considerations

### 1. File Validation

```javascript
const allowedMimeTypes = ['application/pdf'];
const maxFileSize = 10 * 1024 * 1024; // 10MB

const fileFilter = (req, file, cb) => {
    if (allowedMimeTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Only PDF files are allowed'), false);
    }
};
```

### 2. Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 requests per windowMs
    message: 'Too many upload attempts, please try again later.'
});

app.use('/api/upload', uploadLimiter);
```

### 3. Authentication Middleware

```javascript
const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Apply to upload route
app.post("/api/upload", authenticateToken, upload, async (req, res) => {
    // ... upload logic
});
```

## Error Handling

### 1. Comprehensive Error Handling

```javascript
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                error: 'File too large',
                message: 'File size must be less than 10MB'
            });
        }
    }
    
    if (error.message === 'Only PDF files are allowed') {
        return res.status(400).json({
            error: 'Invalid file type',
            message: 'Only PDF files are allowed'
        });
    }
    
    console.error('Unhandled error:', error);
    res.status(500).json({
        error: 'Internal server error',
        message: 'Something went wrong'
    });
});
```

### 2. AWS Error Handling

```javascript
try {
    await s3.send(uploadCommand);
} catch (error) {
    if (error.name === 'NoSuchBucket') {
        return res.status(500).json({
            error: 'Storage configuration error',
            message: 'S3 bucket not found'
        });
    }
    
    if (error.name === 'AccessDenied') {
        return res.status(500).json({
            error: 'Storage access denied',
            message: 'Insufficient permissions'
        });
    }
    
    throw error;
}
```

## Production Deployment

### 1. Environment Variables

Ensure all environment variables are properly set in production:

```bash
# Production .env
NODE_ENV=production
PORT=8080
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-production-access-key
AWS_SECRET_ACCESS_KEY=your-production-secret-key
S3_BUCKET_NAME=your-production-bucket
```

### 2. Docker Configuration

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 8080

CMD ["npm", "start"]
```

### 3. Docker Compose

```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - NODE_ENV=production
      - AWS_REGION=${AWS_REGION}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - S3_BUCKET_NAME=${S3_BUCKET_NAME}
    volumes:
      - ./uploads:/app/uploads
```

### 4. Health Check

```javascript
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});
```

## Additional Features

### 1. File Deletion

```javascript
const { DeleteObjectCommand } = require('@aws-sdk/client-s3');

app.delete('/api/delete/:fileKey', async (req, res) => {
    try {
        const deleteCommand = new DeleteObjectCommand({
            Bucket: process.env.S3_BUCKET_NAME,
            Key: req.params.fileKey
        });
        
        await s3.send(deleteCommand);
        res.json({ success: true, message: 'File deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete file', details: error.message });
    }
});
```

### 2. File Listing

```javascript
const { ListObjectsV2Command } = require('@aws-sdk/client-s3');

app.get('/api/files', async (req, res) => {
    try {
        const listCommand = new ListObjectsV2Command({
            Bucket: process.env.S3_BUCKET_NAME,
            Prefix: 'uploads/reports/'
        });
        
        const response = await s3.send(listCommand);
        res.json({ files: response.Contents || [] });
    } catch (error) {
        res.status(500).json({ error: 'Failed to list files', details: error.message });
    }
});
```

## Troubleshooting

### Common Issues

1. **CORS Errors**: Ensure CORS is properly configured for your frontend domain
2. **File Size Limits**: Check both Multer limits and AWS S3 limits
3. **Authentication Errors**: Verify AWS credentials and IAM permissions
4. **Bucket Access**: Ensure bucket exists and is accessible
5. **File Type Validation**: Check MIME type validation logic

### Debug Mode

```javascript
// Enable detailed logging
process.env.DEBUG = 'true';

if (process.env.DEBUG === 'true') {
    console.log('AWS Configuration:', {
        region: process.env.AWS_REGION,
        bucket: process.env.S3_BUCKET_NAME,
        hasAccessKey: !!process.env.AWS_ACCESS_KEY_ID,
        hasSecretKey: !!process.env.AWS_SECRET_ACCESS_KEY
    });
}
```

## Conclusion

This implementation provides a robust, production-ready solution for uploading PDF files to AWS S3. The code includes proper error handling, security measures, and can be easily adapted for other file types or use cases.

Remember to:
- Keep your AWS credentials secure
- Implement proper authentication
- Monitor file uploads and storage usage
- Regularly update dependencies
- Test thoroughly before deploying to production

For questions or issues, refer to the AWS S3 documentation or the Node.js AWS SDK documentation.

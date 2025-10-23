# AWS S3 PDF Upload Setup Guide

## Environment Variables Required

Add these environment variables to your `.env` file:

```env
# AWS S3 Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
S3_BUCKET_NAME=your-bucket-name
```

## AWS S3 Setup Steps

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

## API Endpoints

### Upload PDF
- **POST** `/api/upload`
- **Content-Type**: `multipart/form-data`
- **Body**: Form data with `pdfFile` field

### Delete PDF
- **DELETE** `/api/delete/:fileKey`
- **Parameters**: `fileKey` - S3 object key

### List Files
- **GET** `/api/files`
- **Query Parameters**: `prefix` (optional, default: `uploads/reports/`)

## Testing

### Using cURL
```bash
curl -X POST \
  http://localhost:5000/api/upload \
  -H 'Content-Type: multipart/form-data' \
  -F 'pdfFile=@/path/to/your/file.pdf'
```

### Using PowerShell
```powershell
$filePath = "C:\path\to\your\file.pdf"
$form = @{
    pdfFile = Get-Item $filePath
}
Invoke-WebRequest -Uri "http://localhost:5000/api/upload" -Method POST -Form $form
```

## Frontend Integration

### HTML Form
```html
<form id="pdfUploadForm" enctype="multipart/form-data">
    <div>
        <label for="pdfFile">Select PDF File:</label>
        <input type="file" id="pdfFile" name="pdfFile" accept=".pdf" required>
    </div>
    <button type="submit">Upload PDF</button>
</form>

<script>
document.getElementById('pdfUploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData();
    const fileInput = document.getElementById('pdfFile');
    
    if (fileInput.files.length === 0) {
        alert('Please select a PDF file');
        return;
    }
    
    formData.append('pdfFile', fileInput.files[0]);
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            console.log('Upload successful:', result.uploaded[0].url);
        } else {
            console.error('Upload failed:', result.error);
        }
    } catch (error) {
        console.error('Error:', error);
    }
});
</script>
```

### React Component
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
            setResult({ success: false, error: error.message });
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

## Error Handling

The API returns structured error responses:

```json
{
    "success": false,
    "error": "Error type",
    "message": "Human readable message",
    "details": "Technical details"
}
```

Common error types:
- `AWS configuration missing` - Missing AWS credentials
- `File too large` - File exceeds 10MB limit
- `Invalid file type` - Non-PDF file uploaded
- `Storage configuration error` - S3 bucket not found
- `Storage access denied` - Insufficient AWS permissions

## Security Considerations

1. **File Validation**: Only PDF files are allowed
2. **Size Limits**: 10MB maximum file size
3. **AWS Credentials**: Store securely in environment variables
4. **CORS**: Configure properly for your frontend domains
5. **Authentication**: Add authentication middleware if needed

## Production Deployment

1. Set production environment variables
2. Use IAM roles instead of access keys when possible
3. Enable S3 bucket logging
4. Set up CloudWatch monitoring
5. Implement rate limiting for upload endpoints

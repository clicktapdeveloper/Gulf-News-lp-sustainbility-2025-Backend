// server.ts / index.ts

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import multer from 'multer';
import Stripe from 'stripe';
import QRCode from 'qrcode';
import clientPromise from './utils/mongodb.js';
import { sendEmail } from './utils/mailer.js';
import { createCardPayment, CyberSourceClient } from './utils/cybersource.js';
import { createS3Service } from './utils/s3.js';

const app = express();
const PORT = process.env.PORT || 5000;

// ---- Configure trusted frontend origins explicitly
// Support comma-separated env like: FRONTEND_URLS=http://localhost:5173,http://localhost:3000,https://app.example.com
const FRONTEND_URLS = (process.env.FRONTEND_URLS || process.env.FRONTEND_URL || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// Sensible local defaults if env not set
if (FRONTEND_URLS.length === 0) {
  FRONTEND_URLS.push('http://localhost:5173', 'http://localhost:3000', 'https://gulf-news-vite.vercel.app');
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '', { apiVersion: '2023-10-16' });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1, // Only one file
    fields: 5, // Maximum 5 fields
    parts: 10 // Maximum 10 parts
  },
  fileFilter: (req, file, cb) => {
    console.log('File filter check:', file.mimetype, file.originalname);
    // Allow PDF files
    if (file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf')) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'), false);
    }
  }
}).single('pdfFile');

// ---- CORS: dynamic allowlist
app.use(
  cors({
    origin(origin, cb) {
      // allow non-browser requests (curl/postman) with no origin
      if (!origin) return cb(null, true);
      return cb(null, FRONTEND_URLS.includes(origin));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true, // keep true only if you actually use cookies
    optionsSuccessStatus: 204,
  })
);

// (Optional) handle explicit preflights
app.options('*', cors());

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'OK', message: 'Gulf News API is running' });
});

// ==================== CYBERSOURCE CHARGE ====================
app.post('/api/payments/cybersource/charge', async (req, res) => {
  try {
    const { amount, currency = 'AED', transientToken, referenceId, customerEmail, nominationData } = req.body || {};

    if (!amount || !transientToken) {
      return res.status(400).json({ error: 'amount and transientToken are required' });
    }

    const { data } = await createCardPayment({ amount, currency, transientToken, referenceId, customerEmail });

    // Check if this is a successful nomination payment
    if (data?.status === 'AUTHORIZED' && nominationData && customerEmail) {
      console.log('CyberSource nomination payment successful, sending confirmation email');
      
      // Save nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      const nomination = {
        ...nominationData,
        paymentAmount: parseFloat(amount),
        paymentCurrency: currency,
        paymentMethod: 'cybersource',
        paymentReference: data?.id,
        paymentStatus: 'completed',
        submittedAt: new Date(),
        status: 'submitted',
        cybersourceTransactionId: data?.id,
        reconciliationId: data?.processorInformation?.reconciliationId,
        networkTransactionId: data?.processorInformation?.networkTransactionId
      };

      await db.collection('nominations').insertOne(nomination);

      // Send nomination confirmation email
      await sendNominationConfirmationEmail(customerEmail, nomination);
    } else if (data?.status === 'AUTHORIZED' && nominationData?.email) {
      // Fallback: if customerEmail is not provided but nominationData has email
      console.log('CyberSource nomination payment successful (fallback), sending confirmation email to:', nominationData.email);
      
      // Save nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      const nomination = {
        ...nominationData,
        paymentAmount: parseFloat(amount),
        paymentCurrency: currency,
        paymentMethod: 'cybersource',
        paymentReference: data?.id,
        paymentStatus: 'completed',
        submittedAt: new Date(),
        status: 'submitted',
        cybersourceTransactionId: data?.id,
        reconciliationId: data?.processorInformation?.reconciliationId,
        networkTransactionId: data?.processorInformation?.networkTransactionId
      };

      await db.collection('nominations').insertOne(nomination);

      // Send nomination confirmation email
      await sendNominationConfirmationEmail(nominationData.email, nomination);
    }

    // Map CyberSource response minimally
    return res.json({
      success: true,
      id: data?.id,
      status: data?.status,
      reconciliationId: data?.processorInformation?.reconciliationId,
      networkTransactionId: data?.processorInformation?.networkTransactionId,
    });
  } catch (error) {
    console.error('CyberSource charge error:', error?.response?.text || error);
    return res.status(502).json({ error: 'Payment authorization failed' });
  }
});

// ==================== CYBERSOURCE PAYMENT PROCESSING ====================
app.post('/api/payments/cybersource/process', async (req, res) => {
  try {
    const { amount, currency = 'AED', cardNumber, expiryMonth, expiryYear, cvv, customerEmail, nominationData } = req.body || {};

    console.log('Payment Request Received:', {
      amount,
      currency,
      cardNumber: cardNumber ? `${cardNumber.substring(0, 4)}...` : 'NOT_PROVIDED',
      expiryMonth,
      expiryYear,
      cvv: cvv ? 'PROVIDED' : 'NOT_PROVIDED',
      hasNominationData: !!nominationData,
      customerEmail: customerEmail ? 'PROVIDED' : 'NOT_PROVIDED'
    });

    if (!amount || !cardNumber || !expiryMonth || !expiryYear || !cvv) {
      return res.status(400).json({ 
        success: false,
        error: 'amount, cardNumber, expiryMonth, expiryYear, and cvv are required',
        details: {
          provided: {
            amount: !!amount,
            cardNumber: !!cardNumber,
            expiryMonth: !!expiryMonth,
            expiryYear: !!expiryYear,
            cvv: !!cvv
          }
        }
      });
    }

    // Validate environment variables
    const merchantID = process.env.CYBERSOURCE_MERCHANT_ID || process.env.CYBS_MERCHANT_ID;
    const keyId = process.env.CYBERSOURCE_KEY_ID || process.env.CYBS_API_KEY_ID;
    const secretKey = process.env.CYBERSOURCE_SECRET_KEY || process.env.CYBS_API_SECRET_KEY;
    const runEnvironment = process.env.CYBERSOURCE_RUN_ENVIRONMENT || process.env.CYBS_HOST || 'apitest.cybersource.com';

    if (!merchantID || !keyId || !secretKey) {
      return res.status(500).json({
        success: false,
        error: 'CyberSource configuration missing',
        details: {
          merchantID: !!merchantID,
          keyId: !!keyId,
          secretKey: !!secretKey,
          runEnvironment
        }
      });
    }

    const client = new CyberSourceClient({
      merchantID,
      keyId,
      secretKey,
      runEnvironment
    });

    const result = await client.createPayment({
      amount: String(amount),
      currency: currency.toUpperCase(),
      cardNumber: String(cardNumber).replace(/\s/g, ''),
      expiryMonth: String(expiryMonth).padStart(2, '0'),
      expiryYear: String(expiryYear),
      cvv: String(cvv)
    });

    // Check if this is a successful nomination payment
    if (result.status === 'AUTHORIZED' && nominationData && customerEmail) {
      console.log('CyberSource nomination payment successful, sending confirmation email');
      
      // Save nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      const nomination = {
        ...nominationData,
        paymentAmount: parseFloat(amount),
        paymentCurrency: currency,
        paymentMethod: 'cybersource',
        paymentReference: result.id,
        paymentStatus: 'completed',
        submittedAt: new Date(),
        status: 'submitted',
        cybersourceTransactionId: result.id,
        reconciliationId: result.processorInformation?.reconciliationId,
        networkTransactionId: result.processorInformation?.networkTransactionId
      };

      await db.collection('nominations').insertOne(nomination);

      // Send nomination confirmation email
      await sendNominationConfirmationEmail(customerEmail, nomination);
    } else if (result.status === 'AUTHORIZED' && nominationData?.email) {
      // Fallback: if customerEmail is not provided but nominationData has email
      console.log('CyberSource nomination payment successful (fallback), sending confirmation email to:', nominationData.email);
      
      // Save nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      const nomination = {
        ...nominationData,
        paymentAmount: parseFloat(amount),
        paymentCurrency: currency,
        paymentMethod: 'cybersource',
        paymentReference: result.id,
        paymentStatus: 'completed',
        submittedAt: new Date(),
        status: 'submitted',
        cybersourceTransactionId: result.id,
        reconciliationId: result.processorInformation?.reconciliationId,
        networkTransactionId: result.processorInformation?.networkTransactionId
      };

      await db.collection('nominations').insertOne(nomination);

      // Send nomination confirmation email
      await sendNominationConfirmationEmail(nominationData.email, nomination);
    } else if (result.status === 'AUTHORIZED') {
      // Debug: Log what we received for successful payments
      console.log('CyberSource payment successful but no nomination email sent. Debug info:');
      console.log('- nominationData:', !!nominationData);
      console.log('- customerEmail:', !!customerEmail);
      console.log('- nominationData?.email:', !!nominationData?.email);
      console.log('- Full request body keys:', Object.keys(req.body || {}));
    }

    return res.json({
      success: true,
      paymentId: result.id,
      status: result.status,
      response: result
    });

  } catch (error) {
    console.error('CyberSource payment processing error:', error);
    
    // Provide more specific error messages
    let errorMessage = 'Payment processing failed';
    let errorDetails = error.message;

    if (error.message.includes('fetch failed')) {
      errorMessage = 'Unable to connect to CyberSource API';
      errorDetails = 'Check your CyberSource credentials and network connection';
    } else if (error.message.includes('SSL')) {
      errorMessage = 'SSL connection failed';
      errorDetails = 'CyberSource API SSL handshake failed';
    } else if (error.message.includes('Authentication')) {
      errorMessage = 'Authentication failed';
      errorDetails = 'Invalid CyberSource credentials';
    } else if (error.message.includes('required')) {
      errorMessage = 'Configuration error';
      errorDetails = error.message;
    }
    
    return res.status(400).json({
      success: false,
      error: errorMessage,
      details: errorDetails,
      originalError: error.message
    });
  }
});

// ==================== CYBERSOURCE TOKEN CREATION ====================
app.post('/api/payments/cybersource/token', async (req, res) => {
  try {
    const { cardNumber, expiryMonth, expiryYear, cvv } = req.body || {};

    if (!cardNumber || !expiryMonth || !expiryYear || !cvv) {
      return res.status(400).json({ 
        error: 'cardNumber, expiryMonth, expiryYear, and cvv are required' 
      });
    }

    const client = new CyberSourceClient({
      merchantID: process.env.CYBERSOURCE_MERCHANT_ID || process.env.CYBS_MERCHANT_ID || '',
      keyId: process.env.CYBERSOURCE_KEY_ID || process.env.CYBS_API_KEY_ID || '',
      secretKey: process.env.CYBERSOURCE_SECRET_KEY || process.env.CYBS_API_SECRET_KEY || '',
      runEnvironment: process.env.CYBERSOURCE_RUN_ENVIRONMENT || process.env.CYBS_HOST || 'apitest.cybersource.com'
    });

    const result = await client.createToken({
      amount: '0.00',
      currency: 'AED',
      cardNumber,
      expiryMonth,
      expiryYear,
      cvv
    });

    return res.json({
      success: true,
      tokenId: result.id,
      status: result.status,
      response: result
    });

  } catch (error) {
    console.error('CyberSource token creation error:', error);
    
    return res.status(400).json({
      success: false,
      error: error.message || 'Token creation failed',
      details: error
    });
  }
});

// ==================== CYBERSOURCE SIGNATURE TEST ====================
app.post('/api/payments/cybersource/signature-test', async (req, res) => {
  try {
    const timestamp = new Date().toISOString();
    const payload = { test: true };
    const payloadString = JSON.stringify(payload);
    const digest = `SHA-256=${crypto.createHash('sha256').update(payloadString).digest('base64')}`;
    
    const signatureString = `host: ${process.env.CYBERSOURCE_RUN_ENVIRONMENT || process.env.CYBS_HOST || 'apitest.cybersource.com'}\n` +
                           `date: ${timestamp}\n` +
                           `(request-target): post /pts/v2/payments\n` +
                           `digest: ${digest}\n` +
                           `v-c-merchant-id: ${process.env.CYBERSOURCE_MERCHANT_ID || process.env.CYBS_MERCHANT_ID || ''}`;

    const rawSignature = crypto
      .createHmac('sha256', process.env.CYBERSOURCE_SECRET_KEY || process.env.CYBS_API_SECRET_KEY || '')
      .update(signatureString)
      .digest('base64');

    return res.json({
      success: true,
      debug: {
        timestamp,
        digest,
        signatureString,
        rawSignature,
        headers: {
          'Content-Type': 'application/json',
          'v-c-merchant-id': process.env.CYBERSOURCE_MERCHANT_ID || process.env.CYBS_MERCHANT_ID || '',
          'Date': timestamp,
          'Host': process.env.CYBERSOURCE_RUN_ENVIRONMENT || process.env.CYBS_HOST || 'apitest.cybersource.com',
          'Digest': digest,
          'Signature': `keyid="${process.env.CYBERSOURCE_KEY_ID || process.env.CYBS_API_KEY_ID || ''}", algorithm="HmacSHA256", headers="host date (request-target) digest v-c-merchant-id", signature="${rawSignature}"`
        }
      }
    });

  } catch (error) {
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// ==================== CYBERSOURCE CONFIG CHECK ====================
app.get('/api/payments/cybersource/config-check', async (req, res) => {
  try {
    const merchantID = process.env.CYBERSOURCE_MERCHANT_ID || process.env.CYBS_MERCHANT_ID;
    const keyId = process.env.CYBERSOURCE_KEY_ID || process.env.CYBS_API_KEY_ID;
    const secretKey = process.env.CYBERSOURCE_SECRET_KEY || process.env.CYBS_API_SECRET_KEY;
    const runEnvironment = process.env.CYBERSOURCE_RUN_ENVIRONMENT || process.env.CYBS_HOST || 'apitest.cybersource.com';

    const configStatus = {
      merchantID: {
        set: !!merchantID,
        value: merchantID ? `${merchantID.substring(0, 4)}...` : 'NOT_SET',
        source: merchantID ? (process.env.CYBERSOURCE_MERCHANT_ID ? 'CYBERSOURCE_MERCHANT_ID' : 'CYBS_MERCHANT_ID') : 'NONE'
      },
      keyId: {
        set: !!keyId,
        value: keyId ? `${keyId.substring(0, 4)}...` : 'NOT_SET',
        source: keyId ? (process.env.CYBERSOURCE_KEY_ID ? 'CYBERSOURCE_KEY_ID' : 'CYBS_API_KEY_ID') : 'NONE'
      },
      secretKey: {
        set: !!secretKey,
        value: secretKey ? 'SET' : 'NOT_SET',
        source: secretKey ? (process.env.CYBERSOURCE_SECRET_KEY ? 'CYBERSOURCE_SECRET_KEY' : 'CYBS_API_SECRET_KEY') : 'NONE'
      },
      runEnvironment: {
        value: runEnvironment,
        source: 'apitest.cybersource.com'
        // source: process.env.CYBERSOURCE_RUN_ENVIRONMENT ? 'CYBERSOURCE_RUN_ENVIRONMENT' : 
        //        process.env.CYBS_HOST ? 'CYBS_HOST' : 'DEFAULT'
      }
    };

    const allConfigured = merchantID && keyId && secretKey;

    return res.json({
      success: true,
      configured: allConfigured,
      config: configStatus,
      message: allConfigured ? 'CyberSource configuration is complete' : 'CyberSource configuration is incomplete'
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Failed to check configuration',
      details: error.message
    });
  }
});

// ==================== PDF S3 UPLOAD ====================
app.post('/api/upload', upload, async (req, res) => {
  console.log("=== PDF UPLOAD REQUEST RECEIVED ===");
  console.log("Request file:", req.file);
  console.log("Request body:", req.body);
  
  if (!req.file) {
    return res.status(400).json({ 
      success: false,
      error: "No file uploaded", 
      message: "Please select a PDF file to upload"
    });
  }

  try {
    const s3Service = createS3Service();
    
    console.log('Processing file:', {
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      fieldname: req.file.fieldname
    });
    
    const result = await s3Service.uploadFile(
      req.file.buffer,
      req.file.originalname,
      req.file.mimetype,
      'uploads/reports'
    );
    
    const uploadedMeta = {
      type: req.file.fieldname,
      url: result.url,
      key: result.key,
      originalname: result.originalName,
      fieldname: req.file.fieldname,
      mimetype: result.mimetype,
      size: result.size,
      uploadedAt: result.uploadedAt
    };

    console.log("Uploaded file:", uploadedMeta);
    res.json({ 
      success: true,
      uploaded: [uploadedMeta],
      message: "PDF uploaded successfully"
    });

  } catch (err) {
    console.error('Upload error:', err.name, err.message, err.stack);
    
    // Handle specific AWS errors
    if (err.message.includes('AWS_ACCESS_KEY_ID is required') || 
        err.message.includes('AWS_SECRET_ACCESS_KEY is required') || 
        err.message.includes('S3_BUCKET_NAME is required')) {
      return res.status(500).json({ 
        success: false,
        error: 'AWS configuration missing', 
        message: 'Please configure AWS credentials and S3 bucket name'
      });
    }
    
    if (err.message.includes('NoSuchBucket')) {
      return res.status(500).json({ 
        success: false,
        error: 'Storage configuration error', 
        message: 'S3 bucket not found'
      });
    }
    
    if (err.message.includes('AccessDenied')) {
      return res.status(500).json({ 
        success: false,
        error: 'Storage access denied', 
        message: 'Insufficient AWS permissions'
      });
    }
    
    res.status(500).json({ 
      success: false,
      error: 'Upload failed', 
      details: err.message 
    });
  }
});

// ==================== PDF DELETE ====================
app.delete('/api/delete/:fileKey', async (req, res) => {
  try {
    const { fileKey } = req.params;
    
    if (!fileKey) {
      return res.status(400).json({
        success: false,
        error: 'File key is required'
      });
    }
    
    const s3Service = createS3Service();
    await s3Service.deleteFile(fileKey);
    
    res.json({ 
      success: true, 
      message: 'File deleted successfully' 
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to delete file', 
      details: error.message 
    });
  }
});

// ==================== PDF LIST ====================
app.get('/api/files', async (req, res) => {
  try {
    const { prefix = 'uploads/reports/' } = req.query;
    
    const s3Service = createS3Service();
    const files = await s3Service.listFiles(prefix);
    
    res.json({ 
      success: true,
      files: files,
      count: files.length
    });
  } catch (error) {
    console.error('List files error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to list files', 
      details: error.message 
    });
  }
});

// Error handling middleware for multer errors
app.use((error, req, res, next) => {
  console.error('Error middleware caught:', error.message);
  
  if (error instanceof multer.MulterError) {
    console.error('Multer error:', error.code);
    
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large',
        message: 'File size must be less than 10MB'
      });
    }
    
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        success: false,
        error: 'Too many files',
        message: 'Only one file allowed per upload'
      });
    }
    
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        error: 'Unexpected file field',
        message: 'Use field name "pdfFile"'
      });
    }
    
    return res.status(400).json({
      success: false,
      error: 'File upload error',
      message: error.message
    });
  }
  
  if (error.message === 'Only PDF files are allowed') {
    return res.status(400).json({
      success: false,
      error: 'Invalid file type',
      message: 'Only PDF files are allowed'
    });
  }
  
  if (error.message.includes('Unexpected end of form')) {
    return res.status(400).json({
      success: false,
      error: 'Invalid form data',
      message: 'Please ensure the file is properly uploaded'
    });
  }
  
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: 'Something went wrong'
  });
});

// Helper: pick a trusted base URL for redirects (don't trust request headers)
function getFrontendBase() {
  // Prefer explicit FRONTEND_URL (single) or first in FRONTEND_URLS
  return process.env.FRONTEND_URL || FRONTEND_URLS[0];
}

// ==================== CHECKOUT SESSIONS ====================
app.post('/api/checkout_sessions', async (req, res) => {
  try {
    const body = req.body;
    const { type } = body;

    const base = getFrontendBase(); // trusted, not req.headers.origin

    if (type === 'nomination') {
      const { amount, nominationData } = body;

      const lineItems = [
        {
          price_data: {
            currency: 'aed',
            product_data: {
              name: `Nomination Submission - ${nominationData.category}`,
              description: `Nomination fee for ${nominationData.category} category`,
            },
            unit_amount: Math.round(amount * 100),
          },
          quantity: 1,
        },
      ];

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'payment',
        line_items: lineItems,
        success_url: `${base}/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${base}/cancel`,
        metadata: {
          type: 'nomination',
          nominationData: JSON.stringify(nominationData),
        },
        customer_email: nominationData.email,
      });

      return res.json({ url: session.url });
    } else {
      const { attendees, ticketPrice, eventName, eventDate, eventLocation } = body;

      if (!attendees || attendees.length === 0) {
        return res.status(400).json({ error: 'At least one attendee is required' });
      }

      const lineItems = [
        {
          price_data: {
            currency: 'aed',
            product_data: {
              name: `${eventName} - Ticket`,
              description: `${eventDate} | ${eventLocation}`,
            },
            unit_amount: Math.round(ticketPrice * 100),
          },
          quantity: attendees.length,
        },
      ];

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'payment',
        line_items: lineItems,
        success_url: `${base}/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${base}/cancel`,
        metadata: {
          type: 'event_ticket',
          eventName,
          eventDate,
          eventLocation,
          attendeeCount: attendees.length.toString(),
          attendeesData: JSON.stringify(attendees),
        },
        customer_email: attendees[0].email,
      });

      return res.json({ url: session.url });
    }
  } catch (error) {
    console.error('Error creating checkout session:', error);
    return res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// ==================== REGISTER ATTENDEE ====================
app.post('/api/register-attendee', async (req, res) => {
  try {
    const body = req.body;
    const { firstName, lastName, email, phone, company, position, industry, interests, dietaryRequirements } = body;

    // Save registration to database (optional)
    // You can add MongoDB integration here if needed

    // Send confirmation email to attendee
    await sendRegistrationConfirmationEmail(email, body);

    // Send notification email to admin
    await sendRegistrationNotificationEmail(body);

    return res.json({
      success: true,
      message: 'Registration submitted successfully'
    });
  } catch (error) {
    console.error('Error submitting registration:', error);
    return res.status(500).json({ error: 'Failed to submit registration' });
  }
});

async function sendRegistrationConfirmationEmail(email, data) {
  const eventName = process.env.NEXT_PUBLIC_EVENT_NAME || 'Annual Tech Conference 2025';
  const eventDate = process.env.NEXT_PUBLIC_EVENT_DATE || 'December 15, 2025';
  const eventLocation = process.env.NEXT_PUBLIC_EVENT_LOCATION || 'Grand Convention Center, Dubai';

  const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Registration Confirmation</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">🎉 Registration Confirmed!</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">You're all set for the event</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">
                Hello, ${data.firstName} ${data.lastName}!
              </h2>
              <p style="margin: 0 0 30px; color: #000000; font-size: 16px; line-height: 1.6;">
                Thank you for registering! We're excited to have you join us for ${eventName}.
              </p>
            </td>
          </tr>

          <!-- Event Details -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #E7FB7A; border-radius: 12px; padding: 30px;">
                <tr>
                  <td>
                    <h3 style="margin: 0 0 20px; color: #224442; font-size: 20px; font-weight: bold;">${eventName}</h3>
                    <table width="100%" cellpadding="8" cellspacing="0">
                      <tr>
                        <td style="color: #000000; font-size: 14px; width: 100px;">📅 Date:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${eventDate}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">📍 Location:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${eventLocation}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">👤 Attendee:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${data.firstName} ${data.lastName}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          ${data.interests && data.interests.length > 0 ? `
          <!-- Interests -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <h3 style="margin: 0 0 15px; color: #224442; font-size: 18px;">Your Interests:</h3>
              <div style="background-color: #DBE2CD; padding: 20px; border-radius: 8px;">
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                  ${data.interests.map(interest => `
                    <span style="background-color: #224442; color: #FFFFFF; padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;">
                      ${interest}
                    </span>
                  `).join('')}
                </div>
              </div>
            </td>
          </tr>
          ` : ''}

          <!-- What to Expect -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <h3 style="margin: 0 0 20px; color: #224442; font-size: 18px; text-align: center;">What to Expect</h3>
              <table width="100%" cellpadding="15" cellspacing="0">
                <tr>
                  <td style="text-align: center; vertical-align: top; width: 33.33%;">
                    <div style="font-size: 32px; margin-bottom: 10px;">🎯</div>
                    <h4 style="margin: 0 0 8px; color: #224442; font-size: 14px; font-weight: 600;">Keynote Sessions</h4>
                    <p style="margin: 0; color: #000000; font-size: 12px;">Industry insights from experts</p>
                  </td>
                  <td style="text-align: center; vertical-align: top; width: 33.33%;">
                    <div style="font-size: 32px; margin-bottom: 10px;">🤝</div>
                    <h4 style="margin: 0 0 8px; color: #224442; font-size: 14px; font-weight: 600;">Networking</h4>
                    <p style="margin: 0; color: #000000; font-size: 12px;">Connect with professionals</p>
                  </td>
                  <td style="text-align: center; vertical-align: top; width: 33.33%;">
                    <div style="font-size: 32px; margin-bottom: 10px;">🍽️</div>
                    <h4 style="margin: 0 0 8px; color: #224442; font-size: 14px; font-weight: 600;">Refreshments</h4>
                    <p style="margin: 0; color: #000000; font-size: 12px;">Food and beverages provided</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Important Information -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <div style="background-color: #E7FB7A; border-left: 4px solid #224442; border-radius: 8px; padding: 20px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">📋 Important Information</h4>
                <ul style="margin: 0; padding-left: 20px; color: #000000; font-size: 14px; line-height: 1.8;">
                  <li>Please arrive 30 minutes early for check-in</li>
                  <li>Bring a valid photo ID for verification</li>
                  <li>Dress code: Business casual</li>
                  <li>WiFi and charging stations will be available</li>
                  ${data.dietaryRequirements ? `<li>We've noted your dietary requirements: ${data.dietaryRequirements}</li>` : ''}
                </ul>
              </div>
            </td>
          </tr>

          <!-- Need Help Section -->
          <tr>
            <td style="padding: 0 40px 40px; text-align: center;">
              <div style="background-color: #DBE2CD; border-radius: 8px; padding: 25px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">Need Help?</h4>
                <p style="margin: 0 0 15px; color: #000000; font-size: 14px;">Our support team is here to assist you</p>
                <div style="flex flex-col sm:flex-row gap-2 justify-center text-sm">
                  <a href="mailto:support@yourevent.com" style="color: #224442; font-weight: 600; text-decoration: none;">
                    📧 support@yourevent.com
                  </a>
                  <span className="hidden sm:inline text-gray-400">|</span>
                  <a href="tel:+971501234567" style="color: #224442; font-weight: 600; text-decoration: none;">
                    📞 +971 50 123 4567
                  </a>
                </div>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0 0 10px; color: #224442; font-size: 18px; font-weight: 600;">We're looking forward to seeing you! 🎊</p>
              <p style="margin: 0; color: #000000; font-size: 12px;">
                © ${new Date().getFullYear()} Event Registration. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  await sendEmail({
    to: email,
    subject: `🎉 Registration Confirmed - ${eventName}`,
    html: emailHtml,
  });
}

async function sendRegistrationNotificationEmail(data) {
  const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>New Registration</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">🎉 New Registration</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">A new attendee has registered for the event</p>
            </td>
          </tr>

          <!-- Registration Details -->
          <tr>
            <td style="padding: 40px;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">Registration Details</h2>
              
              <table width="100%" cellpadding="12" cellspacing="0" style="background-color: #DBE2CD; border-radius: 8px; border: 1px solid #00000040;">
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600; width: 150px;">Name:</td>
                  <td style="color: #000000; font-size: 14px;">${data.firstName} ${data.lastName}</td>
                </tr>
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Email:</td>
                  <td style="color: #000000; font-size: 14px;"><a href="mailto:${data.email}" style="color: #224442;">${data.email}</a></td>
                </tr>
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Phone:</td>
                  <td style="color: #000000; font-size: 14px;"><a href="tel:${data.phone}" style="color: #224442;">${data.phone}</a></td>
                </tr>
              </table>

              ${data.interests && data.interests.length > 0 ? `
                <div style="margin-top: 20px;">
                  <h3 style="color: #224442; font-size: 16px; margin-bottom: 10px;">Interests:</h3>
                  <div style="background-color: #E7FB7A; padding: 15px; border-radius: 8px;">
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                      ${data.interests.map(interest => `
                        <span style="background-color: #224442; color: #FFFFFF; padding: 4px 8px; border-radius: 12px; font-size: 12px;">
                          ${interest}
                        </span>
                      `).join('')}
                    </div>
                  </div>
                </div>
              ` : ''}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0; color: #000000; font-size: 12px;">
                © ${new Date().getFullYear()} Event Registration System. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  // Send to admin email
  const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
  
  await sendEmail({
    to: adminEmail,
    subject: `🎉 New Registration: ${data.firstName} ${data.lastName}`,
    html: emailHtml,
  });
}

// ==================== SPONSORSHIP ====================
app.post('/api/sponsorship', async (req, res) => {
  try {
    const body = req.body;
    console.log('Received sponsorship data:', body);
    
    // Extract fields from contact form (mapping form fields to expected names)
    const {
      firstName,        // Full Name from form
      lastName,         // Could be part of Full Name
      companyName,      // Company Name from form
      designation,      // Designation from form
      email,           // Email from form
      phone,           // Phone from form
      tradeLicense,    // Trade License from form
      supportingDocument, // Supporting Document from form
      message          // Message from form
    } = body;

    // Create contact person name (combine firstName and lastName if available)
    const contactPerson = lastName ? `${firstName} ${lastName}` : firstName;

    // Create sponsorship data object
    const sponsorshipData = {
      contactPerson,
      companyName: companyName || 'Not specified',
      email,
      phone,
      designation: designation || 'Not specified',
      tradeLicense: tradeLicense || 'Not provided',
      supportingDocument: supportingDocument || 'Not provided',
      message: message || 'No additional message',
      submittedAt: new Date(),
      status: 'submitted'
    };

    // Save sponsorship request to database (optional)
    // You can add MongoDB integration here if needed

    // Send confirmation email to sponsor
    await sendSponsorshipConfirmationEmail(email, sponsorshipData);

    // Send notification email to admin
    await sendSponsorshipNotificationEmail(sponsorshipData);

    return res.json({
      success: true,
      message: 'Sponsorship request submitted successfully'
    });
  } catch (error) {
    console.error('Error submitting sponsorship request:', error);
    return res.status(500).json({ error: 'Failed to submit sponsorship request' });
  }
});

// ==================== NOMINATION ====================
app.post('/api/nomination', async (req, res) => {
  try {
    const body = req.body;
    console.log('Received nomination data:', body);

    // Extract nomination data from the payload
    const {
      firstName,
      lastName,
      email,
      companyName2,
      designation,
      phone,
      tradeLicense,
      supportingDocument,
      message,
      paymentAmount,
      paymentCurrency,
      paymentDate,
      paymentReference,
      paymentStatus
    } = body;

    // Validate required fields
    if (!firstName || !lastName) {
      return res.status(400).json({ 
        error: 'Missing required fields: firstName and lastName are required' 
      });
    }

    // Connect to MongoDB
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    // Create nomination document
    const nomination = {
      firstName,
      lastName,
      email,
      companyName: companyName2,
      designation,
      phone,
      tradeLicense,
      supportingDocument,
      message,
      paymentAmount: parseFloat(paymentAmount) || 0,
      paymentCurrency: paymentCurrency || 'AED',
      paymentDate: paymentDate ? new Date(paymentDate) : new Date(),
      paymentReference,
      paymentStatus: paymentStatus || 'completed',
      submittedAt: new Date(),
      status: 'submitted'
    };

    // Save nomination to database
    const result = await db.collection('nominations').insertOne(nomination);
    
    console.log('Nomination saved successfully:', result.insertedId);

    // Send confirmation email if we have email data
    if (nomination.email) {
      console.log('Sending nomination confirmation email to:', nomination.email);
      await sendNominationConfirmationEmail(nomination.email, nomination);
    } else {
      console.log('No email found in nomination data, skipping email notification');
    }

    return res.json({
      success: true,
      message: 'Nomination submitted successfully',
      nominationId: result.insertedId,
      nomination
    });

  } catch (error) {
    console.error('Error submitting nomination:', error);
    return res.status(500).json({ 
      error: 'Failed to submit nomination',
      details: error.message 
    });
  }
});

async function sendSponsorshipConfirmationEmail(email, data) {
  const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sponsorship Request Confirmation</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">🤝 Sponsorship Request Received!</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">Thank you for your interest in partnering with us</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">
                Hello, ${data.contactPerson}!
              </h2>
              <p style="margin: 0 0 30px; color: #000000; font-size: 16px; line-height: 1.6;">
                Thank you for your sponsorship request. We're excited about the possibility of partnering your company for our upcoming event.
              </p>
            </td>
          </tr>

          <!-- Request Details -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #E7FB7A; border-radius: 12px; padding: 30px;">
                <tr>
                  <td>
                    <h3 style="margin: 0 0 20px; color: #224442; font-size: 20px; font-weight: bold;">Your Sponsorship Request Details</h3>
                    <table width="100%" cellpadding="8" cellspacing="0">
                      <tr>
                        <td style="color: #000000; font-size: 14px; width: 150px;">Contact Person:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${data.contactPerson}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Email:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${data.email}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Phone:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${data.phone}</td>
                      </tr>
                      ${data.supportingDocument && data.supportingDocument !== 'Not provided' ? `
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Supporting Document:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">
                          <a href="${data.supportingDocument}" style="color: #224442;" target="_blank">View Document</a>
                        </td>
                      </tr>
                      ` : ''}
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Next Steps -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <div style="background-color: #E7FB7A; border-left: 4px solid #224442; border-radius: 8px; padding: 20px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">📋 What Happens Next?</h4>
                <ul style="margin: 0; padding-left: 20px; color: #000000; font-size: 14px; line-height: 1.8;">
                  <li>Our team will review your sponsorship request within 24 hours</li>
                  <li>We'll contact you to discuss partnership opportunities</li>
                  <li>We'll provide detailed sponsorship packages and benefits</li>
                  <li>We'll work together to create a customized sponsorship plan</li>
                </ul>
              </div>
            </td>
          </tr>

          <!-- Contact Information -->
          <tr>
            <td style="padding: 0 40px 40px; text-align: center;">
              <div style="background-color: #DBE2CD; border-radius: 8px; padding: 25px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">Questions?</h4>
                <p style="margin: 0 0 15px; color: #000000; font-size: 14px;">Feel free to reach out to our sponsorship team</p>
                <div className="flex flex-col sm:flex-row gap-2 justify-center text-sm">
                  <a href="mailto:sponsorship@yourevent.com" style="color: #224442; font-weight: 600; text-decoration: none;">
                    📧 sponsorship@yourevent.com
                  </a>
                  <span className="hidden sm:inline text-gray-400">|</span>
                  <a href="tel:+971501234567" style="color: #224442; font-weight: 600; text-decoration: none;">
                    📞 +971 50 123 4567
                  </a>
                </div>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0 0 10px; color: #224442; font-size: 18px; font-weight: 600;">Thank you for your interest! 🤝</p>
              <p style="margin: 0; color: #000000; font-size: 12px;">
                © ${new Date().getFullYear()} Event Sponsorship. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  await sendEmail({
    to: email,
    subject: '🤝 Sponsorship Request Confirmation - Thank You!',
    html: emailHtml,
  });
}

async function sendSponsorshipNotificationEmail(data) {
  const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>New Sponsorship Request</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">🚨 New Sponsorship Request</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">A new sponsorship request has been submitted</p>
            </td>
          </tr>

          <!-- Request Details -->
          <tr>
            <td style="padding: 40px;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">Sponsorship Request Details</h2>
              
              <table width="100%" cellpadding="12" cellspacing="0" style="background-color: #DBE2CD; border-radius: 8px; border: 1px solid #00000040;">
              <tr>
                <td style="color: #224442; font-size: 14px; font-weight: 600;">Contact Person:</td>
                <td style="color: #000000; font-size: 14px;">${data.contactPerson}</td>
              </tr>
              <tr>
                <td style="color: #224442; font-size: 14px; font-weight: 600;">Company:</td>
                <td style="color: #000000; font-size: 14px;">${data.companyName}</td>
              </tr>
              <tr>
                <td style="color: #224442; font-size: 14px; font-weight: 600;">Designation:</td>
                <td style="color: #000000; font-size: 14px;">${data.designation}</td>
              </tr>
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Email:</td>
                  <td style="color: #000000; font-size: 14px;"><a href="mailto:${data.email}" style="color: #224442;">${data.email}</a></td>
                </tr>
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Phone:</td>
                  <td style="color: #000000; font-size: 14px;"><a href="tel:${data.phone}" style="color: #224442;">${data.phone}</a></td>
                </tr>
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Trade License:</td>
                  <td style="color: #000000; font-size: 14px;">${data.tradeLicense}</td>
                </tr>
                ${data.supportingDocument && data.supportingDocument !== 'Not provided' ? `
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Supporting Document:</td>
                  <td style="color: #000000; font-size: 14px;">
                    <a href="${data.supportingDocument}" style="color: #224442;" target="_blank">View Document</a>
                  </td>
                </tr>
                ` : ''}
              </table>

              ${data.message ? `
                <div style="margin-top: 20px;">
                  <h3 style="color: #224442; font-size: 16px; margin-bottom: 10px;">Additional Message:</h3>
                  <div style="background-color: #E7FB7A; padding: 15px; border-radius: 8px; border-left: 4px solid #224442;">
                    <p style="margin: 0; color: #000000; font-size: 14px; line-height: 1.6;">${data.message}</p>
                  </div>
                </div>
              ` : ''}

              <div style="margin-top: 30px; text-align: center;">
                <a href="mailto:${data.email}" style="display: inline-block; background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); color: #FFFFFF; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-size: 14px; font-weight: 600;">
                  Reply to Sponsor
                </a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0; color: #000000; font-size: 12px;">
                © ${new Date().getFullYear()} Event Sponsorship System. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  // Send to admin email (you can set this in environment variables)
  const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
  
  await sendEmail({
    to: adminEmail,
    subject: `🚨 New Sponsorship Request from ${data.companyName}`,
    html: emailHtml,
  });
}

// ==================== VERIFY PAYMENT ====================
app.get('/api/verify-payment', async (req, res) => {
  try {
    const sessionId = req.query.session_id;

    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }

    // Retrieve session from Stripe
    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Payment not completed' });
    }

    const paymentType = session.metadata.type;

    if (paymentType === 'nomination') {
      // Handle nomination payment
      const nominationData = JSON.parse(session.metadata.nominationData);
      
      console.log('Processing nomination payment for:', nominationData);
      console.log('Nomination data email:', nominationData.email);

      // Save nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      const nomination = {
        sessionId,
        ...nominationData,
        paymentAmount: session.amount_total / 100,
        paymentCurrency: session.currency || 'aed',
        paymentMethod: session.payment_method_types?.[0] || 'card',
        submittedAt: new Date().toISOString(),
        status: 'submitted',
      };

      await db.collection('nominations').insertOne(nomination);

      // Send nomination confirmation email only if email is available
      if (nominationData.email) {
        console.log('Sending nomination confirmation email to:', nominationData.email);
        await sendNominationConfirmationEmail(nominationData.email, nomination);
      } else {
        console.log('No email found in nomination data, skipping email notification');
      }

      return res.json({
        success: true,
        message: 'Nomination submitted and payment verified',
        nomination
      });
    } else {
      // Handle event ticket payment (original flow)
      const attendees = JSON.parse(session.metadata.attendeesData);
      const eventName = session.metadata.eventName;
      const eventDate = session.metadata.eventDate;
      const eventLocation = session.metadata.eventLocation;

      // Connect to MongoDB
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');

      // Check if booking already exists
      const existingBooking = await db.collection('bookings').findOne({ sessionId });
      
      if (existingBooking) {
        return res.json({
          success: true,
          message: 'Booking already processed',
          booking: existingBooking
        });
      }

      // Create tickets for each attendee
      const tickets = [];
      for (let i = 0; i < attendees.length; i++) {
        const attendee = attendees[i];
        const ticketId = `TKT-${Date.now()}-${i + 1}`;
        
        // Generate QR code
        const qrData = JSON.stringify({
          ticketId,
          eventName,
          eventDate,
          attendeeName: `${attendee.firstName} ${attendee.lastName}`,
          email: attendee.email,
        });
        
        const qrCodeDataUrl = await QRCode.toDataURL(qrData, {
          width: 300,
          margin: 2,
          color: {
            dark: '#7C3AED',
            light: '#FFFFFF'
          },
          errorCorrectionLevel: 'M'
        });
        
        // Also generate as buffer for attachment
        const qrCodeBuffer = await QRCode.toBuffer(qrData, {
          width: 300,
          margin: 2,
          color: {
            dark: '#7C3AED',
            light: '#FFFFFF'
          },
          errorCorrectionLevel: 'M'
        });

        const ticket = {
          ticketId,
          attendee,
          qrCode: qrCodeDataUrl,
          qrCodeBuffer: qrCodeBuffer,
          status: 'active',
        };

        tickets.push(ticket);
      }

      // Save booking to database
      const booking = {
        sessionId,
        tickets,
        eventName,
        eventDate,
        eventLocation,
        amount: session.amount_total / 100, // Convert from fils to AED
        currency: session.currency || 'aed',
        paymentMethod: session.payment_method_types?.[0] || 'card',
        purchasedAt: new Date().toISOString(),
        status: 'confirmed',
      };

      await db.collection('bookings').insertOne(booking);

      // Send confirmation email to each attendee individually
      console.log(`Sending ${tickets.length} individual emails to attendees...`);
      for (let i = 0; i < tickets.length; i++) {
        const ticket = tickets[i];
        console.log(`Sending email ${i + 1}/${tickets.length} to: ${ticket.attendee.email}`);
        await sendTicketEmail(ticket, booking);
        console.log(`✓ Email sent successfully to ${ticket.attendee.email}`);
      }

      return res.json({
        success: true,
        message: `Payment verified and ${tickets.length} ticket(s) sent to individual emails`,
        booking,
        emailsSent: tickets.map(t => t.attendee.email)
      });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    return res.status(500).json({ error: 'Failed to verify payment' });
  }
});

async function sendTicketEmail(ticket, booking) {
  const { attendee, qrCode, qrCodeBuffer, ticketId } = ticket;
  const { eventName, eventDate, eventLocation, amount, currency } = booking;

  // This function sends a personalized email to EACH individual attendee
  // Each attendee gets their own unique QR code and ticket ID

  const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Event Ticket</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">🎫 Your Ticket is Ready!</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">Thank you for registering</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">
                Hello, ${attendee.firstName} ${attendee.lastName}!
              </h2>
              <p style="margin: 0 0 30px; color: #000000; font-size: 16px; line-height: 1.6;">
                We're excited to welcome you to our event. Your ticket has been confirmed and is ready to use.
              </p>
            </td>
          </tr>

          <!-- Event Details Card -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #E7FB7A; border-radius: 12px; padding: 30px;">
                <tr>
                  <td>
                    <h3 style="margin: 0 0 20px; color: #224442; font-size: 20px; font-weight: bold;">${eventName}</h3>
                    <table width="100%" cellpadding="8" cellspacing="0">
                      <tr>
                        <td style="color: #000000; font-size: 14px; width: 100px;">📅 Date:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${eventDate}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">📍 Location:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${eventLocation}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">🎟️ Ticket ID:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${ticketId}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- QR Code -->
          <tr>
            <td style="padding: 0 40px 30px; text-align: center;">
              <div style="background-color: #DBE2CD; border-radius: 12px; padding: 30px; display: inline-block;">
                <p style="margin: 0 0 20px; color: #000000; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Your Entry Pass</p>
                <img src="cid:qr-code-${ticketId}" alt="Ticket QR Code" style="width: 250px; height: 250px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); border: 2px solid #00000040;" />
                <p style="margin: 20px 0 0; color: #000000; font-size: 13px;">Scan this QR code at the venue entrance</p>
                <p style="margin: 10px 0 0; color: #224442; font-size: 12px; font-weight: 600;">Ticket ID: ${ticketId}</p>
              </div>
            </td>
          </tr>

          <!-- Important Information -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <div style="background-color: #E7FB7A; border-left: 4px solid #224442; border-radius: 8px; padding: 20px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">⚠️ Important Information</h4>
                <ul style="margin: 0; padding-left: 20px; color: #000000; font-size: 14px; line-height: 1.8;">
                  <li>Please bring this QR code (digital or printed) to the event</li>
                  <li>Arrive 30 minutes early for check-in</li>
                  <li>Valid photo ID may be required at the entrance</li>
                  <li>This ticket is non-transferable</li>
                </ul>
              </div>
            </td>
          </tr>

          <!-- What to Expect -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <h3 style="margin: 0 0 20px; color: #224442; font-size: 18px; text-align: center;">What to Expect</h3>
              <table width="100%" cellpadding="15" cellspacing="0">
                <tr>
                  <td style="text-align: center; vertical-align: top; width: 33.33%;">
                    <div style="font-size: 32px; margin-bottom: 10px;">✨</div>
                    <h4 style="margin: 0 0 8px; color: #224442; font-size: 14px; font-weight: 600;">Amazing Experience</h4>
                    <p style="margin: 0; color: #000000; font-size: 12px;">Engaging sessions and activities</p>
                  </td>
                  <td style="text-align: center; vertical-align: top; width: 33.33%;">
                    <div style="font-size: 32px; margin-bottom: 10px;">🤝</div>
                    <h4 style="margin: 0 0 8px; color: #224442; font-size: 14px; font-weight: 600;">Networking</h4>
                    <p style="margin: 0; color: #000000; font-size: 12px;">Meet industry professionals</p>
                  </td>
                  <td style="text-align: center; vertical-align: top; width: 33.33%;">
                    <div style="font-size: 32px; margin-bottom: 10px;">🍽️</div>
                    <h4 style="margin: 0 0 8px; color: #224442; font-size: 14px; font-weight: 600;">Refreshments</h4>
                    <p style="margin: 0; color: #000000; font-size: 12px;">Food and beverages provided</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Need Help Section -->
          <tr>
            <td style="padding: 0 40px 40px; text-align: center;">
              <div style="background-color: #DBE2CD; border-radius: 8px; padding: 25px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">Need Help?</h4>
                <p style="margin: 0 0 15px; color: #000000; font-size: 14px;">Our support team is here to assist you</p>
                <a href="mailto:support@eventticket.com" style="display: inline-block; background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); color: #FFFFFF; text-decoration: none; padding: 12px 30px; border-radius: 8px; font-size: 14px; font-weight: 600;">Contact Support</a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0 0 10px; color: #224442; font-size: 18px; font-weight: 600;">We're looking forward to welcoming you! 🎉</p>
              <p style="margin: 0 0 20px; color: #000000; font-size: 14px;">See you at the event!</p>
              <p style="margin: 0; color: #000000; font-size: 12px;">
                © ${new Date().getFullYear()} Event Ticketing. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  await sendEmail({
    to: attendee.email,
    subject: `🎫 Your Ticket for ${eventName}`,
    html: emailHtml,
    attachments: [{
      filename: `ticket-${ticketId}.png`,
      content: qrCodeBuffer,
      cid: `qr-code-${ticketId}`, // Content ID for embedding in HTML
    }]
  });
}

async function sendNominationConfirmationEmail(email, nomination) {
  // Ensure we have the required data for the email
  const firstName = nomination.firstName || 'Nominee';
  const lastName = nomination.lastName || '';
  const fullName = lastName ? `${firstName} ${lastName}` : firstName;
  
  console.log('Sending nomination confirmation email to:', email);
  console.log('Nomination data:', nomination);
  
  const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nomination Confirmation</title>
</head>
<body style="margin: 0; padding: 0; font-family: 'Arial', sans-serif; background-color: #EBF1E7;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #EBF1E7; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #FFFFFF; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); padding: 40px 40px 30px; text-align: center;">
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">🏆 Nomination Submitted!</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">Thank you for your nomination submission</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">
                Hello, ${fullName}!
              </h2>
              <p style="margin: 0 0 30px; color: #000000; font-size: 16px; line-height: 1.6;">
                Your nomination has been successfully submitted and payment confirmed. We appreciate your interest in our awards program.
              </p>
            </td>
          </tr>

          <!-- Nomination Details -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #E7FB7A; border-radius: 12px; padding: 30px;">
                <tr>
                  <td>
                    <h3 style="margin: 0 0 20px; color: #224442; font-size: 20px; font-weight: bold;">Nomination Details</h3>
                    <table width="100%" cellpadding="8" cellspacing="0">
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Nominee:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${fullName}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Email:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${email}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Company:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${nomination.companyName || 'Not specified'}</td>
                      </tr>
                      <tr>
                        <td style="color: #000000; font-size: 14px;">Payment:</td>
                        <td style="color: #224442; font-size: 14px; font-weight: 600;">${nomination.paymentCurrency || 'AED'} ${nomination.paymentAmount || 0} - Confirmed</td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          ${nomination.description ? `
          <!-- Description -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <h3 style="margin: 0 0 15px; color: #224442; font-size: 18px;">Nomination Description:</h3>
              <div style="background-color: #DBE2CD; padding: 20px; border-radius: 8px; border-left: 4px solid #224442;">
                <p style="margin: 0; color: #000000; font-size: 14px; line-height: 1.6;">${nomination.description}</p>
              </div>
            </td>
          </tr>
          ` : ''}

          ${nomination.supportingDocument ? `
          <!-- Supporting Document -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <h3 style="margin: 0 0 15px; color: #224442; font-size: 18px;">Supporting Document:</h3>
              <div style="background-color: #E7FB7A; padding: 20px; border-radius: 8px; border-left: 4px solid #224442;">
                <p style="margin: 0 0 10px; color: #000000; font-size: 14px; line-height: 1.6;">
                  Your supporting document has been successfully uploaded and attached to your nomination.
                </p>
                <a href="${nomination.supportingDocument}" 
                   style="display: inline-block; background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%); color: #FFFFFF; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 14px; font-weight: 600;">
                  📄 View Supporting Document
                </a>
              </div>
            </td>
          </tr>
          ` : ''}

          <!-- Next Steps -->
          <tr>
            <td style="padding: 0 40px 30px;">
              <div style="background-color: #E7FB7A; border-left: 4px solid #224442; border-radius: 8px; padding: 20px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">📋 What Happens Next?</h4>
                <ul style="margin: 0; padding-left: 20px; color: #000000; font-size: 14px; line-height: 1.8;">
                  <li>Our judging panel will review all nominations</li>
                  <li>You'll be notified of the results within 2 weeks</li>
                  <li>Winners will be announced at the event</li>
                  <li>All nominees will receive recognition</li>
                </ul>
              </div>
            </td>
          </tr>

          <!-- Contact Information -->
          <tr>
            <td style="padding: 0 40px 40px; text-align: center;">
              <div style="background-color: #DBE2CD; border-radius: 8px; padding: 25px;">
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">Questions?</h4>
                <p style="margin: 0 0 15px; color: #000000; font-size: 14px;">Contact our nominations team</p>
                <div style="flex flex-col sm:flex-row gap-2 justify-center text-sm">
                  <a href="mailto:nominations@yourevent.com" style="color: #224442; font-weight: 600; text-decoration: none;">
                    📧 nominations@yourevent.com
                  </a>
                  <span className="hidden sm:inline text-gray-400">|</span>
                  <a href="tel:+971501234567" style="color: #224442; font-weight: 600; text-decoration: none;">
                    📞 +971 50 123 4567
                  </a>
                </div>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #DBE2CD; padding: 30px 40px; text-align: center; border-top: 1px solid #00000040;">
              <p style="margin: 0 0 10px; color: #224442; font-size: 18px; font-weight: 600;">Good luck with your nomination! 🏆</p>
              <p style="margin: 0; color: #000000; font-size: 12px;">
                © ${new Date().getFullYear()} Event Nominations. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  await sendEmail({
    to: email,
    subject: '🏆 Nomination Submitted Successfully - Thank You!',
    html: emailHtml,
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Event Ticketing API Server running on port ${PORT}`);
  console.log(`📡 API endpoints available at http://localhost:${PORT}/api`);
  console.log(`🌍 Accepting requests from: ${process.env.FRONTEND_URL || 'http://localhost:3000' || 'http://localhost:5173'}`);
});


// server.ts / index.ts

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import multer from 'multer';
import Stripe from 'stripe';
import QRCode from 'qrcode';
import { ObjectId } from 'mongodb';
import clientPromise from './utils/mongodb.js';
import { sendEmail } from './utils/mailer.js';
import { createCardPayment, CyberSourceClient } from './utils/cybersource.js';
import { createS3Service } from './utils/s3.js';
import { 
  createPaymentParams, 
  createCyberSourceForm, 
  processPaymentResponse, 
  validateCyberSourceConfig,
  getCyberSourceUrl
} from './utils/cybersource-hosted.js';

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
  FRONTEND_URLS.push('http://localhost:5173', 'http://localhost:3000', 'https://gulf-news-vite.vercel.app', 'https://gulf-news-lp-sustainbility-2025-fro.vercel.app', 'https://www.gulfnews-events.com', 'https://gulfnews-events.com');
}

// Always ensure both www and non-www versions are included for gulfnews-events.com
const gulfNewsDomains = ['https://gulfnews-events.com', 'https://www.gulfnews-events.com'];
gulfNewsDomains.forEach(domain => {
  if (!FRONTEND_URLS.includes(domain)) {
    FRONTEND_URLS.push(domain);
  }
});

console.log('Final FRONTEND_URLS configuration:', FRONTEND_URLS);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '', { apiVersion: '2023-10-16' });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Fail-safe CORS headers for all /api routes (in case upstream/proxy interferes)
app.use('/api', (req, res, next) => {
  const origin = req.headers.origin;
  const isGulfNewsDomain = origin && (
    origin.includes('gulfnews-events.com') ||
    origin.includes('www.gulfnews-events.com')
  );

  if (!origin || FRONTEND_URLS.includes(origin) || isGulfNewsDomain) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Accept, Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    res.header('Vary', 'Origin');

    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
  }

  return next();
});

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
      console.log('CORS Origin check:', origin);
      console.log('Allowed origins:', FRONTEND_URLS);
      
      // allow non-browser requests (curl/postman) with no origin
      if (!origin) {
        console.log('No origin provided, allowing request');
        return cb(null, true);
      }
      
      // Always allow gulfnews-events.com domains
      const isGulfNewsDomain = origin.includes('gulfnews-events.com');
      const isAllowed = FRONTEND_URLS.includes(origin) || isGulfNewsDomain;
      
      console.log('Origin allowed:', isAllowed, 'isGulfNewsDomain:', isGulfNewsDomain);
      
      return cb(null, isAllowed);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Accept', 'Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true, // keep true only if you actually use cookies
    optionsSuccessStatus: 204,
  })
);

// Additional CORS middleware specifically for nomination endpoints
app.use('/api/nomination', (req, res, next) => {
  const origin = req.headers.origin;
  console.log('Nomination endpoint CORS check - Origin:', origin);
  console.log('Nomination endpoint CORS check - Allowed origins:', FRONTEND_URLS);
  
  // Always allow gulfnews-events.com domains
  const isGulfNewsDomain = origin && (
    origin.includes('gulfnews-events.com') || 
    origin.includes('www.gulfnews-events.com')
  );
  
  if (!origin || FRONTEND_URLS.includes(origin) || isGulfNewsDomain) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    
    console.log('CORS headers set for nomination endpoint:', {
      origin,
      allowedOrigin: origin || '*',
      isGulfNewsDomain
    });
    
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
      return;
    }
  } else {
    console.log('CORS request rejected for nomination endpoint:', {
      origin,
      allowedOrigins: FRONTEND_URLS
    });
  }
  
  next();
});

// Additional CORS middleware specifically for new nominations endpoints
app.use('/api/nominations', (req, res, next) => {
  const origin = req.headers.origin;
  console.log('Nominations endpoint CORS check - Origin:', origin);
  console.log('Nominations endpoint CORS check - Allowed origins:', FRONTEND_URLS);
  
  // Always allow gulfnews-events.com domains
  const isGulfNewsDomain = origin && (
    origin.includes('gulfnews-events.com') || 
    origin.includes('www.gulfnews-events.com')
  );
  
  if (!origin || FRONTEND_URLS.includes(origin) || isGulfNewsDomain) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    
    console.log('CORS headers set for nominations endpoint:', {
      origin,
      allowedOrigin: origin || '*',
      isGulfNewsDomain
    });
    
    if (req.method === 'OPTIONS') {
      res.sendStatus(200);
      return;
    }
  } else {
    console.log('CORS request rejected for nominations endpoint:', {
      origin,
      allowedOrigins: FRONTEND_URLS
    });
  }
  
  next();
});

// Handle preflight requests for all endpoints
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  console.log('Preflight request from origin:', origin);
  
  const isGulfNewsDomain = origin && (
    origin.includes('gulfnews-events.com') || 
    origin.includes('www.gulfnews-events.com')
  );

  if (!origin || FRONTEND_URLS.includes(origin) || isGulfNewsDomain) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Accept, Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    res.header('Vary', 'Origin');
  }
  
  res.sendStatus(204);
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'OK', message: 'Gulf News API is running' });
});

// CORS test endpoint
app.get('/api/cors-test', (_req, res) => {
  console.log('CORS Test - Origin:', _req.headers.origin);
  res.json({ 
    status: 'OK', 
    message: 'CORS is working',
    origin: _req.headers.origin,
    allowedOrigins: FRONTEND_URLS,
    timestamp: new Date().toISOString()
  });
});

// Debug endpoint to check CORS configuration
app.get('/api/debug/cors', (_req, res) => {
  res.json({
    status: 'OK',
    message: 'CORS Debug Information',
    requestOrigin: _req.headers.origin,
    allowedOrigins: FRONTEND_URLS,
    isOriginAllowed: !_req.headers.origin || FRONTEND_URLS.includes(_req.headers.origin),
    environment: {
      FRONTEND_URL: process.env.FRONTEND_URL,
      FRONTEND_URLS: process.env.FRONTEND_URLS,
      NODE_ENV: process.env.NODE_ENV
    },
    timestamp: new Date().toISOString()
  });
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

// ==================== CYBERSOURCE HOSTED CHECKOUT ====================

// Add specific CORS headers for CyberSource endpoints
app.use('/api/payments/cybersource-hosted', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }
  next();
});

// Create payment parameters for CyberSource Hosted Checkout (API endpoint)
app.post('/api/payments/cybersource-hosted/create-payment-params', async (req, res) => {
  try {
    console.log('=== CyberSource Payment Params Request ===');
    console.log('Origin:', req.headers.origin);
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);
    
    const { 
      amount, 
      currency = 'AED', 
      customerEmail, 
      customerFirstName, 
      customerLastName, 
      customerAddress, 
      customerCity, 
      customerCountry, 
      nominationData 
    } = req.body;

    console.log('Creating payment parameters for Hosted Checkout');
    console.log('Request data:', req.body);

    // Validate required fields
    if (!amount || !customerEmail) {
      return res.status(400).json({ 
        success: false,
        error: 'amount and customerEmail are required' 
      });
    }

    // Validate CyberSource configuration
    const configValidation = validateCyberSourceConfig();
    if (!configValidation.isValid) {
      return res.status(500).json({
        success: false,
        error: 'CyberSource configuration incomplete',
        missingVariables: configValidation.missingVars
      });
    }

    // Create payment request
    const paymentRequest = {
      customerEmail,
      customerFirstName,
      customerLastName,
      customerAddress,
      customerCity,
      customerCountry,
      amount: parseFloat(amount),
      currency,
      nominationData
    };

    // Generate CyberSource payment parameters
    const paymentParams = createPaymentParams(paymentRequest);

    console.log('Payment parameters created successfully:', {
      amount,
      currency,
      customerEmail,
      referenceNumber: paymentParams.reference_number
    });

    // Return the payment parameters for frontend to use
    return res.json({
      success: true,
      paymentParams,
      cybersourceUrl: getCyberSourceUrl(),
      message: 'Payment parameters created successfully'
    });

  } catch (error) {
    console.error('CyberSource payment parameters creation error:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Failed to create payment parameters',
      details: error.message 
    });
  }
});

// Create nomination payment request with CyberSource Hosted Checkout
app.post('/api/payments/cybersource/nomination-payment', async (req, res) => {
  try {
    const { 
      amount, 
      currency = 'AED', 
      customerEmail, 
      customerFirstName, 
      customerLastName, 
      customerAddress, 
      customerCity, 
      customerCountry, 
      nominationData 
    } = req.body;

    // Validate required fields
    if (!amount || !customerEmail) {
      return res.status(400).json({ 
        success: false,
        error: 'amount and customerEmail are required' 
      });
    }

    // Validate CyberSource configuration
    const configValidation = validateCyberSourceConfig();
    if (!configValidation.isValid) {
      return res.status(500).json({
        success: false,
        error: 'CyberSource configuration incomplete',
        missingVariables: configValidation.missingVars
      });
    }

    // Create payment request
    const paymentRequest = {
      customerEmail,
      customerFirstName,
      customerLastName,
      customerAddress,
      customerCity,
      customerCountry,
      amount: parseFloat(amount),
      currency,
      nominationData
    };

    // Generate CyberSource payment parameters
    const paymentParams = createPaymentParams(paymentRequest);

    // Store nomination data temporarily (you might want to use Redis or database)
    // For now, we'll include it in the reference number for tracking
    console.log('Creating nomination payment request:', {
      amount,
      currency,
      customerEmail,
      referenceNumber: paymentParams.reference_number
    });

    // Return the HTML form for CyberSource redirect
    const htmlForm = createCyberSourceForm(paymentParams);
    
    res.setHeader('Content-Type', 'text/html');
    res.send(htmlForm);

  } catch (error) {
    console.error('CyberSource nomination payment error:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Failed to create payment request',
      details: error.message 
    });
  }
});

// Handle CyberSource return URL (payment result)
app.post('/api/payments/cybersource/return', async (req, res) => {
  try {
    console.log('CyberSource return received:', req.body);

    // Process the payment response
    const paymentResult = processPaymentResponse(req.body);

    console.log('Payment result:', {
      transactionId: paymentResult.transactionId,
      decision: paymentResult.decision,
      isSuccess: paymentResult.isSuccess,
      amount: paymentResult.amount
    });

    if (paymentResult.isSuccess) {
      // Payment was successful - save transaction and nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      // Create transaction record
      const transaction = {
        transactionId: paymentResult.transactionId,
        paymentMethod: 'cybersource_hosted',
        amount: parseFloat(paymentResult.amount),
        currency: paymentResult.currency,
        status: 'completed',
        customerEmail: paymentResult.billToEmail,
        authCode: paymentResult.authCode,
        authTime: paymentResult.authTime,
        cardType: paymentResult.cardType,
        decision: paymentResult.decision,
        reasonCode: paymentResult.reasonCode,
        processorResponse: paymentResult.processorResponse,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Save transaction to transactions collection
      const transactionResult = await db.collection('transactions').insertOne(transaction);
      console.log('Transaction saved successfully:', transactionResult.insertedId);

      // Create nomination record (without transaction details)
      const nomination = {
        customerEmail: paymentResult.billToEmail,
        customerFirstName: paymentResult.billToForename,
        customerLastName: paymentResult.billToSurname,
        transactionId: paymentResult.transactionId,
        submittedAt: new Date(),
        status: 'submitted',
        // Add any additional nomination data here
        nominationData: {} // You might want to store this separately
      };

      await db.collection('nominations').insertOne(nomination);

      // Send nomination confirmation email
      if (nomination.customerEmail) {
        console.log('Sending nomination confirmation email to:', nomination.customerEmail);
        await sendNominationConfirmationEmail(nomination.customerEmail, nomination);
      }

      // Redirect to success page
      const frontendUrl = getFrontendBase();
      return res.redirect(`${frontendUrl}/nomination/success?transaction_id=${paymentResult.transactionId}`);
    } else {
      // Payment failed - redirect to error page
      const frontendUrl = getFrontendBase();
      return res.redirect(`${frontendUrl}/nomination/error?reason=${paymentResult.reasonCode}&message=${encodeURIComponent(paymentResult.message)}`);
    }

  } catch (error) {
    console.error('CyberSource return processing error:', error);
    
    // Redirect to error page
    const frontendUrl = getFrontendBase();
    return res.redirect(`${frontendUrl}/nomination/error?reason=PROCESSING_ERROR&message=${encodeURIComponent('Payment processing failed')}`);
  }
});

// Handle CyberSource cancel URL (user cancelled payment)
app.post('/api/payments/cybersource/cancel', async (req, res) => {
  try {
    console.log('CyberSource payment cancelled:', req.body);
    
    // Redirect to cancel page
    const frontendUrl = getFrontendBase();
    return res.redirect(`${frontendUrl}/nomination/cancelled`);
    
  } catch (error) {
    console.error('CyberSource cancel processing error:', error);
    
    const frontendUrl = getFrontendBase();
    return res.redirect(`${frontendUrl}/nomination/cancelled`);
  }
});

// Test CyberSource Hosted Checkout configuration
app.get('/api/payments/cybersource/hosted-config-check', async (req, res) => {
  try {
    const configValidation = validateCyberSourceConfig();
    
    const configStatus = {
      accessKey: {
        set: !!process.env.CYBERSOURCE_ACCESS_KEY,
        value: process.env.CYBERSOURCE_ACCESS_KEY ? `${process.env.CYBERSOURCE_ACCESS_KEY.substring(0, 8)}...` : 'NOT_SET'
      },
      profileId: {
        set: !!process.env.CYBERSOURCE_PROFILE_ID,
        value: process.env.CYBERSOURCE_PROFILE_ID ? `${process.env.CYBERSOURCE_PROFILE_ID.substring(0, 8)}...` : 'NOT_SET'
      },
      secretKey: {
        set: !!process.env.CYBERSOURCE_SECRET_KEY,
        value: process.env.CYBERSOURCE_SECRET_KEY ? 'SET' : 'NOT_SET'
      },
      environment: {
        value: process.env.CYBERSOURCE_ENVIRONMENT || 'NOT_SET',
        url: process.env.CYBERSOURCE_ENVIRONMENT === 'production' 
          ? 'https://secureacceptance.cybersource.com/pay'
          : 'https://testsecureacceptance.cybersource.com/pay'
      }
    };

    return res.json({
      success: true,
      configured: configValidation.isValid,
      config: configStatus,
      missingVariables: configValidation.missingVars,
      message: configValidation.isValid 
        ? 'CyberSource Hosted Checkout configuration is complete' 
        : 'CyberSource Hosted Checkout configuration is incomplete'
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      error: 'Failed to check CyberSource Hosted Checkout configuration',
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

// ==================== TRANSACTION VERIFICATION ====================

// Get transaction details by ObjectId for verification
app.get('/api/nominations/:id/transaction/:transactionId', async (req, res) => {
  try {
    const { id: nominationId } = req.params;
    const { transactionId } = req.params;
    
    // Validate ObjectId format
    if (!ObjectId.isValid(nominationId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid nomination ID',
        message: 'Nomination ID must be a valid MongoDB ObjectId'
      });
    }

    // Connect to MongoDB
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    // Find nomination by ObjectId
    const nomination = await db.collection('nominations').findOne({ _id: new ObjectId(nominationId) });
    const transactionInfo = await db.collection('transactions').findOne({ transactionId: transactionId });

    if (!nomination) {
      return res.status(404).json({
        success: false,
        error: 'Nomination not found',
        message: 'No nomination found with the provided ID'
      });
    }

    // Update nomination status if email matches and transaction exists
    const nominationEmail = nomination.email || nomination.customerEmail;
    const transactionEmail = transactionInfo?.customerEmail || transactionInfo?.email;
    
    if (transactionInfo && nominationEmail && transactionEmail && 
        nominationEmail.toLowerCase() === transactionEmail.toLowerCase()) {
      console.log('Email match found - updating nomination status to paid');
      
      // Update the nomination status in the database
      await db.collection('nominations').updateOne(
        { _id: new ObjectId(nominationId) },
        { 
          $set: { 
            status: 'paid',
            transactionId: transactionInfo.transactionId || transactionInfo._id.toString(),
            paidAt: new Date()
          } 
        }
      );
      
      nomination.status = 'paid';
      nomination.transactionId = transactionInfo.transactionId || transactionInfo._id.toString();
      console.log('Nomination status updated successfully');
    } else {
      console.log('Email mismatch or missing data:', {
        nominationEmail,
        transactionEmail,
        hasTransactionInfo: !!transactionInfo
      });
    }

    // Return transaction details for verification
    const transactionDetails = {
      _id: nomination._id,
      customerEmail: nomination.email || nomination.customerEmail,
      customerFirstName: nomination.firstName || nomination.customerFirstName,
      customerLastName: nomination.lastName || nomination.customerLastName,
      transactionId: nomination.transactionId,
      submittedAt: nomination.submittedAt,
      status: nomination.status,
      statusUpdated: nomination.status === 'paid' // Indicates if status was just updated
    };

    // Get transaction details from transactions collection
    const transaction = await db.collection('transactions').findOne({ 
      transactionId: nomination.transactionId 
    });

    if (transaction) {
      transactionDetails.paymentAmount = transaction.amount;
      transactionDetails.paymentCurrency = transaction.currency;
      transactionDetails.paymentMethod = transaction.paymentMethod;
      transactionDetails.paymentStatus = transaction.status;
      transactionDetails.paidAt = transaction.createdAt;
      
      // Add CyberSource specific fields if available
      if (transaction.authCode) transactionDetails.authCode = transaction.authCode;
      if (transaction.authTime) transactionDetails.authTime = transaction.authTime;
      if (transaction.cardType) transactionDetails.cardType = transaction.cardType;
      if (transaction.decision) transactionDetails.decision = transaction.decision;
    }

    res.json({
      success: true,
      transaction: transactionDetails,
      message: nomination.status === 'paid' ? 'Nomination status updated to paid' : 'Nomination status unchanged'
    });

  } catch (error) {
    console.error('Get transaction error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get transaction details',
      details: error.message
    });
  }
});

// Update payment status from unpaid to paid (with transaction verification)
app.patch('/api/nominations/:id/payment-status', async (req, res) => {
  try {
    const { id: nominationId } = req.params;
    const { transactionId, email } = req.body;
    
    // Validate ObjectId format
    if (!ObjectId.isValid(nominationId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid nomination ID',
        message: 'Nomination ID must be a valid MongoDB ObjectId'
      });
    }

    // Validate required fields
    if (!transactionId || !email) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields',
        message: 'transactionId and email are required for verification'
      });
    }

    // Connect to MongoDB
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    // Find nomination by ObjectId
    const nomination = await db.collection('nominations').findOne({ _id: new ObjectId(nominationId) });
    
    if (!nomination) {
      return res.status(404).json({
        success: false,
        error: 'Nomination not found',
        message: 'No nomination found with the provided ID'
      });
    }

    // Verify transaction details match
    const emailMatch = (nomination.email || nomination.customerEmail) === email;
    const transactionMatch = nomination.transactionId === transactionId;
    
    if (!emailMatch || !transactionMatch) {
      return res.status(400).json({
        success: false,
        error: 'Transaction verification failed',
        message: 'Email or transaction ID does not match the nomination record',
        details: {
          emailMatch,
          transactionMatch,
          providedEmail: email,
          providedTransactionId: transactionId,
          storedEmail: nomination.email || nomination.customerEmail,
          storedTransactionId: nomination.transactionId
        }
      });
    }

    // Verify transaction exists and is completed
    const transaction = await db.collection('transactions').findOne({ 
      transactionId: transactionId 
    });

    if (!transaction) {
      return res.status(404).json({
        success: false,
        error: 'Transaction not found',
        message: 'No transaction found with the provided transaction ID'
      });
    }

    if (transaction.status !== 'completed') {
      return res.status(400).json({
        success: false,
        error: 'Transaction not completed',
        message: 'Transaction status is not completed'
      });
    }

    // Check if nomination is already paid
    if (nomination.status === 'paid') {
      return res.status(400).json({
        success: false,
        error: 'Nomination already paid',
        message: 'This nomination has already been marked as paid',
        paidAt: nomination.paidAt
      });
    }

    // Update nomination status to paid
    const updateData = {
      status: 'paid',
      paymentStatus: 'completed',
      paidAt: new Date(),
      updatedAt: new Date()
    };

    const result = await db.collection('nominations').updateOne(
      { _id: new ObjectId(nominationId) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: 'Nomination not found',
        message: 'No nomination found with the provided ID'
      });
    }

    if (result.modifiedCount === 0) {
      return res.status(400).json({
        success: false,
        error: 'No changes made',
        message: 'Nomination status was not updated'
      });
    }

    // Get updated nomination for response
    const updatedNomination = await db.collection('nominations').findOne({ _id: new ObjectId(nominationId) });

    res.json({
      success: true,
      message: 'Payment status updated successfully',
      nomination: {
        _id: updatedNomination._id,
        status: updatedNomination.status,
        paymentStatus: updatedNomination.paymentStatus,
        paidAt: updatedNomination.paidAt,
        customerEmail: updatedNomination.email || updatedNomination.customerEmail,
        paymentAmount: updatedNomination.paymentAmount,
        paymentCurrency: updatedNomination.paymentCurrency
      }
    });

  } catch (error) {
    console.error('Update payment status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update payment status',
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

    // Save registration to database
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    const attendeeData = {
      firstName,
      lastName,
      email,
      phone,
      company,
      position,
      industry,
      interests,
      dietaryRequirements,
      submittedAt: new Date(),
      status: 'registered'
    };
    
    const result = await db.collection('attendee_registrations').insertOne(attendeeData);
    console.log('Attendee registration saved successfully:', result.insertedId);

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
  const eventName = process.env.NEXT_PUBLIC_EVENT_NAME || 'The Sustainability Excellence Awards 2025';
  const eventDate = process.env.NEXT_PUBLIC_EVENT_DATE || '';
  const eventLocation = process.env.NEXT_PUBLIC_EVENT_LOCATION || '';

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
              <h1 style="margin: 0; color: #FFFFFF; font-size: 32px; font-weight: bold;">Registration Received</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">${eventName}</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 24px;">Hi ${data.firstName},</h2>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">Thank you for registering to attend ${eventName}.</p>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">We’ve received your registration details. As seats are limited, our team will review and verify your information before confirming your attendance. You’ll receive a follow-up email once your registration is approved.</p>
              <p style="margin: 0; color: #000000; font-size: 16px; line-height: 1.6;">We appreciate your interest in joining this landmark event celebrating sustainability innovation and leadership across the region.</p>
            </td>
          </tr>

          <!-- Event Details (optional) -->
          ${eventDate || eventLocation ? `
          <tr>
            <td style="padding: 0 40px 30px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #E7FB7A; border-radius: 12px; padding: 30px;">
                <tr>
                  <td>
                    <h3 style="margin: 0 0 20px; color: #224442; font-size: 20px; font-weight: bold;">Event Details</h3>
                    <table width="100%" cellpadding="8" cellspacing="0">
                      ${eventDate ? `<tr><td style="color: #000000; font-size: 14px; width: 100px;">📅 Date:</td><td style=\"color: #224442; font-size: 14px; font-weight: 600;\">${eventDate}</td></tr>` : ''}
                      ${eventLocation ? `<tr><td style="color: #000000; font-size: 14px;">📍 Location:</td><td style=\"color: #224442; font-size: 14px; font-weight: 600;\">${eventLocation}</td></tr>` : ''}
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
          ` : ''}

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
                <h4 style="margin: 0 0 10px; color: #224442; font-size: 16px;">📋 Next Steps</h4>
                <ul style="margin: 0; padding-left: 20px; color: #000000; font-size: 14px; line-height: 1.8;">
                  <li>Our team will review your registration due to limited seating</li>
                  <li>You will receive a confirmation email once approved</li>
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
              <p style="margin: 0 0 10px; color: #224442; font-size: 18px; font-weight: 600;">Best regards,<br/>The Sustainability Excellence Awards 2025 Team<br/>Gulf News & BeingShe</p>
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
    subject: `Registration Received – ${eventName}`,
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

// Dedicated CORS middleware for sponsorship endpoint
app.use('/api/sponsorship', (req, res, next) => {
  const origin = req.headers.origin;
  const isGulfNewsDomain = origin && (
    origin.includes('gulfnews-events.com') ||
    origin.includes('www.gulfnews-events.com')
  );

  if (!origin || FRONTEND_URLS.includes(origin) || isGulfNewsDomain) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Accept, Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    res.header('Vary', 'Origin');

    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
  }

  return next();
});

// Explicit OPTIONS handler for sponsorship
app.options('/api/sponsorship', (req, res) => {
  const origin = req.headers.origin;
  const isGulfNewsDomain = origin && (
    origin.includes('gulfnews-events.com') ||
    origin.includes('www.gulfnews-events.com')
  );

  if (!origin || FRONTEND_URLS.includes(origin) || isGulfNewsDomain) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Accept, Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    res.header('Vary', 'Origin');
  }

  return res.sendStatus(204);
});

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

    // Save sponsorship request to database
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    const result = await db.collection('sponsorship_requests').insertOne(sponsorshipData);
    console.log('Sponsorship request saved successfully:', result.insertedId);

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

// ==================== NOMINATION FORM FLOW ====================

// Create Nomination (Initial Submission with 'unpaid' status)
app.post('/api/nominations', async (req, res) => {
  try {
    const body = req.body;
    console.log('Received nomination form data:', body);

    // Extract nomination data from the payload
    const {
      firstName,
      lastName,
      email,
      companyName,
      designation,
      phone,
      category,
      tradeLicense,
      supportingDocument,
      message,
      status = 'unpaid',
      submittedAt
    } = body;

    // Validate required fields
    const requiredFields = ['firstName', 'lastName', 'email', 'companyName', 'designation', 'phone'];
    const missingFields = requiredFields.filter(field => !body[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields',
        missingFields: missingFields,
        message: `The following fields are required: ${missingFields.join(', ')}`
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
        message: 'Please provide a valid email address'
      });
    }

    // Validate phone format (UAE phone number)
    const phoneRegex = /^\+971[0-9]{9}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid phone format',
        message: 'Please provide a valid UAE phone number (+971XXXXXXXXX)'
      });
    }

    // Validate tradeLicense (if provided) - max 1 file
    if (tradeLicense) {
      const tradeLicenseUrls = tradeLicense.split(',').filter(url => url.trim());
      
      if (tradeLicenseUrls.length > 1) {
        return res.status(400).json({ 
          success: false,
          error: 'Only one trade license file is allowed',
          message: 'You can only upload one trade license file'
        });
      }

      // Validate URL format
      if (tradeLicenseUrls.length > 0) {
        const urlRegex = /^https?:\/\/.+/i;
        const url = tradeLicenseUrls[0];
        
        if (!urlRegex.test(url)) {
          return res.status(400).json({ 
            success: false,
            error: 'Invalid trade license URL format',
            message: 'Trade license must be a valid URL starting with http:// or https://'
          });
        }
      }
    }

    // Validate supportingDocument (if provided) - max 3 files
    if (supportingDocument) {
      const supportingUrls = supportingDocument.split(',').filter(url => url.trim());
      
      if (supportingUrls.length > 3) {
        return res.status(400).json({ 
          success: false,
          error: 'Maximum 3 supporting documents allowed',
          message: 'You can only upload a maximum of 3 supporting documents'
        });
      }

      // Validate URL format for each supporting document
      for (const url of supportingUrls) {
        const urlRegex = /^https?:\/\/.+/i;
        if (!urlRegex.test(url)) {
          return res.status(400).json({ 
            success: false,
            error: 'Invalid supporting document URL format',
            message: 'All supporting document URLs must be valid URLs starting with http:// or https://'
          });
        }
      }
    }

    // Validate status
    if (status && !['unpaid', 'paid'].includes(status)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid status',
        message: 'Status must be either "unpaid" or "paid"'
      });
    }

    // Connect to MongoDB
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    // Create nomination document with initial 'unpaid' status
    const nomination = {
      firstName,
      lastName,
      email,
      companyName,
      designation,
      phone,
      category: category || null,
      tradeLicense: tradeLicense || null,
      supportingDocument: supportingDocument || null,
      message: message || null,
      
      // Status tracking
      status: status,
      submittedAt: submittedAt ? new Date(submittedAt) : new Date(),
      paidAt: null,
      
      // Payment information (initially null)
      paymentAmount: null,
      paymentCurrency: null,
      paymentDate: null,
      paymentReference: null,
      paymentStatus: null,
      paymentMethod: null,
      cybersourceTransactionId: null,
      authCode: null,
      authTime: null,
      cardType: null,
      
      // Timestamps
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Save nomination to database
    const result = await db.collection('nominations').insertOne(nomination);
    
    console.log('Nomination created successfully:', result.insertedId);

    return res.json({
      success: true,
      _id: result.insertedId,
      message: 'Nomination created successfully'
    });

  } catch (error) {
    console.error('Error creating nomination:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Failed to create nomination',
      details: error.message 
    });
  }
});

// Update Nomination Payment Status
app.patch('/api/nominations/:nominationId/payment', async (req, res) => {
  try {
    const { nominationId } = req.params;
    const body = req.body;
    
    console.log('Received payment update for nomination:', nominationId);
    console.log('Payment data:', body);

    // Validate nominationId format (MongoDB ObjectId)
    if (!nominationId || nominationId.length !== 24) {
      return res.status(400).json({
        success: false,
        error: 'Invalid nomination ID',
        message: 'Nomination ID must be a valid MongoDB ObjectId'
      });
    }

    // Extract payment data from the payload
    const {
      status,
      paymentAmount,
      paymentCurrency,
      paymentDate,
      paymentReference,
      paymentStatus,
      paymentMethod,
      cybersourceTransactionId,
      authCode,
      authTime,
      cardType,
      paidAt
    } = body;

    // Validate required payment fields
    const requiredPaymentFields = ['status', 'paymentAmount', 'paymentCurrency', 'paymentDate', 'paymentReference', 'paymentStatus', 'paymentMethod'];
    const missingPaymentFields = requiredPaymentFields.filter(field => body[field] === undefined || body[field] === null);
    
    if (missingPaymentFields.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Missing required payment fields',
        missingFields: missingPaymentFields,
        message: `The following payment fields are required: ${missingPaymentFields.join(', ')}`
      });
    }

    // Validate status
    if (status !== 'paid') {
      return res.status(400).json({
        success: false,
        error: 'Invalid status',
        message: 'Status must be "paid" for payment updates'
      });
    }

    // Validate payment amount
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payment amount',
        message: 'Payment amount must be a positive number'
      });
    }

    // Connect to MongoDB
    const client = await clientPromise;
    const db = client.db('eventTicketingDB');
    
    // Check if nomination exists
    const existingNomination = await db.collection('nominations').findOne({ _id: new ObjectId(nominationId) });
    
    if (!existingNomination) {
      return res.status(404).json({
        success: false,
        error: 'Nomination not found',
        message: 'No nomination found with the provided ID'
      });
    }

    // Check if nomination is already paid
    if (existingNomination.status === 'paid') {
      return res.status(400).json({
        success: false,
        error: 'Nomination already paid',
        message: 'This nomination has already been marked as paid'
      });
    }

    // Update nomination with payment information
    const updateData = {
      status: status,
      paymentAmount: parseFloat(paymentAmount),
      paymentCurrency: paymentCurrency,
      paymentDate: paymentDate ? new Date(paymentDate) : new Date(),
      paymentReference: paymentReference,
      paymentStatus: paymentStatus,
      paymentMethod: paymentMethod,
      cybersourceTransactionId: cybersourceTransactionId || null,
      authCode: authCode || null,
      authTime: authTime ? new Date(authTime) : null,
      cardType: cardType || null,
      paidAt: paidAt ? new Date(paidAt) : new Date(),
      updatedAt: new Date()
    };

    const result = await db.collection('nominations').updateOne(
      { _id: new ObjectId(nominationId) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        error: 'Nomination not found',
        message: 'No nomination found with the provided ID'
      });
    }

    console.log('Payment status updated successfully for nomination:', nominationId);

    // Send confirmation email if we have email data
    if (existingNomination.email) {
      console.log('Sending payment confirmation email to:', existingNomination.email);
      
      // Get updated nomination data for email
      const updatedNomination = await db.collection('nominations').findOne({ _id: new ObjectId(nominationId) });
      await sendNominationConfirmationEmail(existingNomination.email, updatedNomination);
    }

    return res.json({
      success: true,
      _id: nominationId,
      message: 'Payment status updated successfully'
    });

  } catch (error) {
    console.error('Error updating nomination payment:', error);
    return res.status(500).json({
      success: false,
      error: 'Failed to update payment status',
      details: error.message
    });
  }
});

// ==================== LEGACY NOMINATION ENDPOINT (for backward compatibility) ====================
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
      category,
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
      category,
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
              <h1 style="margin: 0; color: #FFFFFF; font-size: 24px; font-weight: bold;">Thank You for Your Sponsorship Submission</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">The Sustainability Excellence Awards 2025</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 20px;">Hi ${data.contactPerson},</h2>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">Thank you for your interest in partnering with The Sustainability Excellence Awards 2025.</p>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">We’ve received your sponsorship submission and our partnerships team will review the details shortly.</p>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">As a sponsor, you’ll be joining a landmark platform that celebrates innovation, leadership, and sustainability excellence across the region. Our team will be in touch soon to discuss available partnership options and next steps.</p>
              <p style="margin: 0; color: #000000; font-size: 16px; line-height: 1.6;">We appreciate your support and look forward to collaborating with you on this inaugural event.</p>
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

          <!-- Signature -->
          <tr>
            <td style="padding: 0 40px 30px; text-align: left;">
              <p style="margin: 0; color: #224442; font-size: 16px; font-weight: 600;">Best regards,<br/>The Sustainability Excellence Awards 2025 Team<br/>Gulf News & BeingShe</p>
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
    subject: 'Thank You for Your Sponsorship Submission – The Sustainability Excellence Awards 2025',
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
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Email:</td>
                  <td style="color: #000000; font-size: 14px;"><a href="mailto:${data.email}" style="color: #224442;">${data.email}</a></td>
                </tr>
                <tr>
                  <td style="color: #224442; font-size: 14px; font-weight: 600;">Phone:</td>
                  <td style="color: #000000; font-size: 14px;"><a href="tel:${data.phone}" style="color: #224442;">${data.phone}</a></td>
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

      // Save transaction and nomination to database
      const client = await clientPromise;
      const db = client.db('eventTicketingDB');
      
      // Create transaction record
      const transaction = {
        transactionId: sessionId,
        paymentMethod: 'stripe',
        amount: session.amount_total / 100,
        currency: session.currency || 'aed',
        status: 'completed',
        stripeSessionId: sessionId,
        stripePaymentIntentId: session.payment_intent,
        paymentMethodTypes: session.payment_method_types,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Save transaction to transactions collection
      const transactionResult = await db.collection('transactions').insertOne(transaction);
      console.log('Transaction saved successfully:', transactionResult.insertedId);

      // Create nomination record (without transaction details)
      const nomination = {
        sessionId,
        ...nominationData,
        transactionId: sessionId,
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

      // Create transaction record for event tickets
      const transaction = {
        transactionId: sessionId,
        paymentMethod: 'stripe',
        amount: session.amount_total / 100,
        currency: session.currency || 'aed',
        status: 'completed',
        stripeSessionId: sessionId,
        stripePaymentIntentId: session.payment_intent,
        paymentMethodTypes: session.payment_method_types,
        transactionType: 'event_ticket',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Save transaction to transactions collection
      const transactionResult = await db.collection('transactions').insertOne(transaction);
      console.log('Event ticket transaction saved successfully:', transactionResult.insertedId);

      // Save booking to database (without transaction details)
      const booking = {
        sessionId,
        transactionId: sessionId,
        tickets,
        eventName,
        eventDate,
        eventLocation,
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
              <h1 style="margin: 0; color: #FFFFFF; font-size: 24px; font-weight: bold;">Your Entry Has Been Received</h1>
              <p style="margin: 10px 0 0; color: #FFFFFF; font-size: 16px;">The Sustainability Excellence Awards 2025</p>
            </td>
          </tr>

          <!-- Welcome Message -->
          <tr>
            <td style="padding: 40px; text-align: center;">
              <h2 style="margin: 0 0 20px; color: #224442; font-size: 20px;">Hi ${fullName},</h2>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">Thank you for entering the The Sustainability Excellence Awards 2025.</p>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">We’ve received your nomination for the ${nomination.category ? nomination.category : '[Award Category]'}.</p>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">All entries will be reviewed by our expert judging panel, and shortlisted candidates will be contacted shortly.</p>
              <p style="margin: 0 0 15px; color: #000000; font-size: 16px; line-height: 1.6;">If shortlisted, you’ll also gain access to exclusive editorial and media opportunities across Gulf News platforms — designed to highlight your achievements and innovation in the industry.</p>
              <p style="margin: 0; color: #000000; font-size: 16px; line-height: 1.6;">We’re excited to have you as part of this first-ever event and look forward to celebrating the region’s sustainability leaders.</p>
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

          <!-- Signature -->
          <tr>
            <td style="padding: 0 40px 30px; text-align: left;">
              <p style="margin: 0; color: #224442; font-size: 16px; font-weight: 600;">Best regards,<br/>The Sustainability Excellence Awards 2025 Team<br/>Gulf News & BeingShe</p>
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
              <p style="margin: 0 0 10px; color: #224442; font-size: 18px; font-weight: 600;">Best regards,<br/>The Sustainability Excellence Awards 2025 Team<br/>Gulf News & BeingShe</p>
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
    subject: 'Your Entry Has Been Received – The Sustainability Excellence Awards 2025',
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


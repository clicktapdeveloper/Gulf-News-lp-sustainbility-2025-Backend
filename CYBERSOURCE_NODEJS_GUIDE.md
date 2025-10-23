# CyberSource Payment Gateway Integration - Node.js Configuration Guide

## 📋 Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Account Setup](#account-setup)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Implementation](#implementation)
7. [API Endpoints](#api-endpoints)
8. [Testing](#testing)
9. [Troubleshooting](#troubleshooting)
10. [Security Best Practices](#security-best-practices)

## 🎯 Overview

This guide covers the complete setup and integration of CyberSource payment gateway with Node.js applications. CyberSource provides secure payment processing capabilities for credit cards, digital wallets, and alternative payment methods.

### Key Features
- ✅ Direct payment processing
- ✅ Payment tokenization
- ✅ Fraud detection
- ✅ Multi-currency support
- ✅ PCI DSS compliance

## 🔧 Prerequisites

### Required Software
- Node.js 16+ 
- npm or yarn package manager
- CyberSource merchant account

### Required Knowledge
- Basic Node.js/JavaScript
- REST API concepts
- HTTP authentication methods

## 🏢 Account Setup

### Step 1: Create CyberSource Account
1. Visit [CyberSource Developer Portal](https://developer.cybersource.com/)
2. Sign up for a developer account
3. Complete business verification process

### Step 2: Access EBC2 Portal
1. Log into [EBC2 Test Environment](https://ebc2test.cybersource.com/ebc2)
2. Navigate to your merchant profile
3. Note your **Merchant ID**

### Step 3: Generate API Credentials
1. Go to **Security** → **API Keys**
2. Click **"Generate New API Key"**
3. Select **Sandbox** environment
4. Choose **Payment Processing** permissions
5. Copy your **Key ID** and **Secret Key**

### Step 4: Enable Required Services
In EBC2 portal, enable:
- ✅ **Simple Order API**
- ✅ **Payment Tokenization Service**
- ✅ **REST API** access

## 📦 Installation

### Option 1: Direct HTTP Implementation (Recommended)
```bash
# No additional packages needed - using native Node.js crypto
npm install crypto
```

### Option 2: Official SDK (Alternative)
```bash
npm install cybersource-rest-client
```

## ⚙️ Configuration

### Environment Variables
Create a `.env.local` file:

```bash
# CyberSource Configuration
CYBERSOURCE_MERCHANT_ID=your_merchant_id
CYBERSOURCE_KEY_ID=your_key_id
CYBERSOURCE_SECRET_KEY=your_secret_key
CYBERSOURCE_RUN_ENVIRONMENT=apitest.cybersource.com
```

### Configuration File
Create `src/lib/cybersource-config.ts`:

```typescript
export const cybersourceConfig = {
  merchantID: process.env.CYBERSOURCE_MERCHANT_ID || 'your_merchant_id',
  keyId: process.env.CYBERSOURCE_KEY_ID || 'your_key_id',
  secretKey: process.env.CYBERSOURCE_SECRET_KEY || 'your_secret_key',
  runEnvironment: process.env.CYBERSOURCE_RUN_ENVIRONMENT || 'apitest.cybersource.com'
};

// Debug logging (remove in production)
if (process.env.NODE_ENV === 'development') {
  console.log('CyberSource Config:', {
    merchantID: cybersourceConfig.merchantID,
    keyId: cybersourceConfig.keyId,
    secretKey: cybersourceConfig.secretKey ? '***hidden***' : 'NOT_SET',
    runEnvironment: cybersourceConfig.runEnvironment
  });
}
```

## 🔨 Implementation

### CyberSource Client Class
Create `src/lib/cybersource-client.ts`:

```typescript
import crypto from 'crypto';

export interface CyberSourceConfig {
  merchantID: string;
  keyId: string;
  secretKey: string;
  runEnvironment: string;
}

export interface PaymentRequest {
  amount: string;
  currency: string;
  cardNumber: string;
  expiryMonth: string;
  expiryYear: string;
  cvv: string;
}

export interface PaymentResponse {
  id: string;
  status: string;
  statusInformation?: {
    reason: string;
    message: string;
  };
  processorInformation?: {
    responseCode: string;
    responseMessage: string;
  };
}

class CyberSourceClient {
  private config: CyberSourceConfig;

  constructor(config: CyberSourceConfig) {
    this.config = config;
  }

  private generateDigest(payload: string): string {
    const hash = crypto.createHash('sha256').update(payload).digest('base64');
    return `SHA-256=${hash}`;
  }

  private generateSignature(method: string, resourcePath: string, payload: string, timestamp: string, digest: string): string {
    const signatureString = `host: ${this.config.runEnvironment}\n` +
                           `date: ${timestamp}\n` +
                           `(request-target): ${method.toLowerCase()} ${resourcePath}\n` +
                           `digest: ${digest}\n` +
                           `v-c-merchant-id: ${this.config.merchantID}`;

    // Try both raw secret key and base64 decoded secret key
    let signature: string;
    try {
      const decodedSecret = Buffer.from(this.config.secretKey, 'base64');
      signature = crypto
        .createHmac('sha256', decodedSecret)
        .update(signatureString)
        .digest('base64');
    } catch (error) {
      signature = crypto
        .createHmac('sha256', this.config.secretKey)
        .update(signatureString)
        .digest('base64');
    }

    return signature;
  }

  private async makeRequest(method: string, resourcePath: string, payload?: any): Promise<any> {
    const timestamp = new Date().toISOString();
    const payloadString = payload ? JSON.stringify(payload) : '';
    const digest = this.generateDigest(payloadString);
    const signature = this.generateSignature(method, resourcePath, payloadString, timestamp, digest);

    const headers = {
      'Content-Type': 'application/json',
      'v-c-merchant-id': this.config.merchantID,
      'Date': timestamp,
      'Host': this.config.runEnvironment,
      'Digest': digest,
      'Signature': `keyid="${this.config.keyId}", algorithm="HmacSHA256", headers="host date (request-target) digest v-c-merchant-id", signature="${signature}"`
    };

    const url = `https://${this.config.runEnvironment}${resourcePath}`;

    const response = await fetch(url, {
      method,
      headers,
      body: payloadString || undefined
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    return await response.json();
  }

  async createPayment(paymentData: PaymentRequest): Promise<PaymentResponse> {
    const payload = {
      clientReferenceInformation: {
        code: `TC${Date.now()}`
      },
      paymentInformation: {
        card: {
          number: paymentData.cardNumber,
          expirationMonth: paymentData.expiryMonth,
          expirationYear: paymentData.expiryYear,
          securityCode: paymentData.cvv
        }
      },
      orderInformation: {
        amountDetails: {
          totalAmount: paymentData.amount,
          currency: paymentData.currency
        },
        billTo: {
          firstName: "John",
          lastName: "Doe",
          address1: "1 Market St",
          locality: "San Francisco",
          administrativeArea: "CA",
          postalCode: "94105",
          country: "US",
          email: "test@cybs.com",
          phoneNumber: "4158880000"
        }
      }
    };

    return await this.makeRequest('POST', '/pts/v2/payments', payload);
  }

  async createToken(paymentData: PaymentRequest): Promise<PaymentResponse> {
    const payload = {
      clientReferenceInformation: {
        code: `TC${Date.now()}`
      },
      paymentInformation: {
        card: {
          number: paymentData.cardNumber,
          expirationMonth: paymentData.expiryMonth,
          expirationYear: paymentData.expiryYear,
          securityCode: paymentData.cvv
        }
      }
    };

    return await this.makeRequest('POST', '/tms/v2/tokens', payload);
  }
}

export default CyberSourceClient;
```

## 🌐 API Endpoints

### Payment Processing API
Create `src/app/api/payment/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import CyberSourceClient from '@/lib/cybersource-client';
import { cybersourceConfig } from '@/lib/cybersource-config';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { amount, currency, cardNumber, expiryMonth, expiryYear, cvv } = body;

    const client = new CyberSourceClient(cybersourceConfig);

    const result = await client.createPayment({
      amount,
      currency: currency || 'USD',
      cardNumber,
      expiryMonth,
      expiryYear,
      cvv
    });

    return NextResponse.json({
      success: true,
      paymentId: result.id,
      status: result.status,
      response: result
    });

  } catch (error: any) {
    console.error('Payment processing error:', error);
    
    return NextResponse.json({
      success: false,
      error: error.message || 'Payment processing failed',
      details: error.response?.data || error
    }, { status: 400 });
  }
}
```

### Token Creation API
Create `src/app/api/token/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import CyberSourceClient from '@/lib/cybersource-client';
import { cybersourceConfig } from '@/lib/cybersource-config';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { cardNumber, expiryMonth, expiryYear, cvv } = body;

    const client = new CyberSourceClient(cybersourceConfig);

    const result = await client.createToken({
      amount: '0.00',
      currency: 'USD',
      cardNumber,
      expiryMonth,
      expiryYear,
      cvv
    });

    return NextResponse.json({
      success: true,
      tokenId: result.id,
      status: result.status,
      response: result
    });

  } catch (error: any) {
    console.error('Token creation error:', error);
    
    return NextResponse.json({
      success: false,
      error: error.message || 'Token creation failed',
      details: error.response?.data || error
    }, { status: 400 });
  }
}
```

## 🧪 Testing

### Test Card Numbers
Use these test card numbers (they won't charge real money):

| Card Type | Number | CVV | Expiry |
|-----------|--------|-----|--------|
| Visa | 4111111111111111 | Any 3 digits | Any future date |
| Mastercard | 5555555555554444 | Any 3 digits | Any future date |
| American Express | 378282246310005 | Any 4 digits | Any future date |
| Discover | 6011111111111117 | Any 3 digits | Any future date |

### Test Payment Request
```javascript
const testPayment = {
  amount: "10.00",
  currency: "USD",
  cardNumber: "4111111111111111",
  expiryMonth: "12",
  expiryYear: "2025",
  cvv: "123"
};

const response = await fetch('/api/payment', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(testPayment)
});

const result = await response.json();
console.log(result);
```

### Expected Success Response
```json
{
  "success": true,
  "paymentId": "1234567890123456789012",
  "status": "AUTHORIZED",
  "response": {
    "id": "1234567890123456789012",
    "status": "AUTHORIZED",
    "submitTimeUtc": "2023-12-01T10:30:00.000Z",
    "processorInformation": {
      "responseCode": "00",
      "responseMessage": "Approved"
    }
  }
}
```

## 🐛 Troubleshooting

### Common Errors and Solutions

#### 1. "INVALID_DATA" Error
**Cause**: Incorrect JSON structure or missing required fields
**Solution**: 
- Verify JSON payload structure matches CyberSource requirements
- Ensure all required fields are present
- Check data types (amounts as strings, dates as proper format)

#### 2. "Authentication Failed" Error
**Cause**: Incorrect signature generation or invalid credentials
**Solution**:
- Verify API credentials are correct
- Check if secret key needs base64 decoding
- Ensure API key is active in EBC2 portal
- Verify signature string order and format

#### 3. "Service Not Enabled" Error
**Cause**: Required services not enabled in EBC2
**Solution**:
- Enable Simple Order API in EBC2 portal
- Enable Payment Tokenization Service
- Verify REST API access is enabled

#### 4. "Invalid Merchant" Error
**Cause**: Wrong merchant ID or inactive account
**Solution**:
- Verify merchant ID is correct
- Check account status in EBC2 portal
- Ensure test account is active

### Debug Tools

#### Signature Test Endpoint
Create `src/app/api/signature-test/route.ts` for debugging:

```typescript
import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { cybersourceConfig } from '@/lib/cybersource-config';

export async function POST(request: NextRequest) {
  try {
    const timestamp = new Date().toISOString();
    const payload = { test: true };
    const payloadString = JSON.stringify(payload);
    const digest = `SHA-256=${crypto.createHash('sha256').update(payloadString).digest('base64')}`;
    
    const signatureString = `host: ${cybersourceConfig.runEnvironment}\n` +
                           `date: ${timestamp}\n` +
                           `(request-target): post /pts/v2/payments\n` +
                           `digest: ${digest}\n` +
                           `v-c-merchant-id: ${cybersourceConfig.merchantID}`;

    const rawSignature = crypto
      .createHmac('sha256', cybersourceConfig.secretKey)
      .update(signatureString)
      .digest('base64');

    return NextResponse.json({
      success: true,
      debug: {
        timestamp,
        digest,
        signatureString,
        rawSignature,
        headers: {
          'Content-Type': 'application/json',
          'v-c-merchant-id': cybersourceConfig.merchantID,
          'Date': timestamp,
          'Host': cybersourceConfig.runEnvironment,
          'Digest': digest,
          'Signature': `keyid="${cybersourceConfig.keyId}", algorithm="HmacSHA256", headers="host date (request-target) digest v-c-merchant-id", signature="${rawSignature}"`
        }
      }
    });

  } catch (error: any) {
    return NextResponse.json({
      success: false,
      error: error.message
    }, { status: 400 });
  }
}
```

## 🔒 Security Best Practices

### 1. Environment Variables
- Never commit credentials to version control
- Use environment variables for all sensitive data
- Use different credentials for test and production

### 2. Input Validation
```typescript
// Validate card number format
const validateCardNumber = (cardNumber: string): boolean => {
  const cleanNumber = cardNumber.replace(/\s/g, '');
  return /^\d{13,19}$/.test(cleanNumber);
};

// Validate expiry date
const validateExpiryDate = (month: string, year: string): boolean => {
  const expiryDate = new Date(parseInt(year), parseInt(month) - 1);
  return expiryDate > new Date();
};
```

### 3. Error Handling
```typescript
try {
  const result = await client.createPayment(paymentData);
  // Handle success
} catch (error) {
  // Log error securely (don't expose sensitive data)
  console.error('Payment failed:', error.message);
  
  // Return generic error to client
  return NextResponse.json({
    success: false,
    error: 'Payment processing failed'
  }, { status: 400 });
}
```

### 4. PCI Compliance
- Never store card details in your database
- Use tokens for recurring payments
- Implement proper access controls
- Regular security audits

### 5. Rate Limiting
```typescript
// Implement rate limiting for payment endpoints
const rateLimit = new Map();

export async function POST(request: NextRequest) {
  const clientIP = request.ip || 'unknown';
  const now = Date.now();
  
  if (rateLimit.has(clientIP)) {
    const lastRequest = rateLimit.get(clientIP);
    if (now - lastRequest < 1000) { // 1 second limit
      return NextResponse.json({
        error: 'Rate limit exceeded'
      }, { status: 429 });
    }
  }
  
  rateLimit.set(clientIP, now);
  // Continue with payment processing
}
```

## 📚 Additional Resources

### Documentation
- [CyberSource Developer Portal](https://developer.cybersource.com/)
- [REST API Documentation](https://developer.cybersource.com/docs)
- [Test Card Numbers](https://developer.cybersource.com/docs)

### Support
- CyberSource Support Portal
- Developer Community Forums
- Technical Support Hotline

### Sample Projects
- [CyberSource Node.js Samples](https://github.com/CyberSource/cybersource-rest-client-node)
- [Payment Integration Examples](https://developer.cybersource.com/docs)

---

## 📝 Changelog

### Version 1.0.0
- Initial implementation
- Direct payment processing
- Token creation
- Basic error handling

### Version 1.1.0
- Enhanced signature generation
- Debug tools
- Comprehensive error handling
- Security improvements

---

**Last Updated**: December 2024  
**Maintained By**: Development Team  
**License**: MIT


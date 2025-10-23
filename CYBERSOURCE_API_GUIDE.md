# CyberSource Payment Gateway API Integration Guide

This guide provides comprehensive instructions for integrating with the CyberSource payment gateway APIs in your application.

## 📋 Table of Contents

1. [API Overview](#api-overview)
2. [Authentication](#authentication)
3. [Available Endpoints](#available-endpoints)
4. [Frontend Integration Examples](#frontend-integration-examples)
5. [Error Handling](#error-handling)
6. [Testing](#testing)
7. [Security Best Practices](#security-best-practices)

## 🌐 API Overview

The CyberSource payment gateway provides three main endpoints for different payment scenarios:

- **Direct Payment Processing** - Process payments immediately with card details
- **Token Creation** - Create reusable payment tokens
- **Legacy Charge** - Backward compatibility with existing transient token payments

**Base URL:** `http://localhost:5000/api/payments/cybersource`

### 🚨 Important Notes

1. **SSL Handshake Issues**: If you encounter SSL handshake failures, ensure your CyberSource credentials are properly configured
2. **Test Environment**: Always use test card numbers for development
3. **Error Handling**: Implement proper error handling for network failures and API errors

## 🔐 Authentication

All API endpoints require proper environment variables to be set:

```bash
# Required Environment Variables
CYBERSOURCE_MERCHANT_ID=your_merchant_id
CYBERSOURCE_KEY_ID=your_key_id
CYBERSOURCE_SECRET_KEY=your_secret_key
CYBERSOURCE_RUN_ENVIRONMENT=apitest.cybersource.com
```

## 🚀 Available Endpoints

### 1. Direct Payment Processing

**Endpoint:** `POST /api/payments/cybersource/process`

**Use Case:** Process payments immediately when you have card details from the user.

**Request Body:**
```json
{
  "amount": "10.00",
  "currency": "AED",
  "cardNumber": "4111111111111111",
  "expiryMonth": "12",
  "expiryYear": "2025",
  "cvv": "123"
}
```

**Response (Success):**
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

**Response (Error):**
```json
{
  "success": false,
  "error": "Payment processing failed",
  "details": "INVALID_DATA: Missing required field"
}
```

### 2. Payment Token Creation

**Endpoint:** `POST /api/payments/cybersource/token`

**Use Case:** Create reusable payment tokens for future transactions or subscription payments.

**Request Body:**
```json
{
  "cardNumber": "4111111111111111",
  "expiryMonth": "12",
  "expiryYear": "2025",
  "cvv": "123"
}
```

**Response (Success):**
```json
{
  "success": true,
  "tokenId": "1234567890123456789012",
  "status": "CREATED",
  "response": {
    "id": "1234567890123456789012",
    "status": "CREATED",
    "submitTimeUtc": "2023-12-01T10:30:00.000Z"
  }
}
```

### 3. Legacy Charge (Transient Token)

**Endpoint:** `POST /api/payments/cybersource/charge`

**Use Case:** Process payments using CyberSource's transient token (for existing integrations).

**Request Body:**
```json
{
  "amount": "10.00",
  "currency": "AED",
  "transientToken": "jwt_token_here",
  "referenceId": "ORDER-123456",
  "customerEmail": "customer@example.com"
}
```

### 4. Signature Test (Debug)

**Endpoint:** `POST /api/payments/cybersource/signature-test`

**Use Case:** Test signature generation for debugging authentication issues.

**Request Body:** Empty `{}`

## 💻 Frontend Integration Examples

### Complete Payment Service Class

```javascript
class CyberSourcePaymentService {
  constructor(baseURL = '/api/payments/cybersource') {
    this.baseURL = baseURL;
  }

  /**
   * Process a payment with card details
   * @param {Object} paymentData - Payment information
   * @returns {Promise<Object>} Payment result
   */
  async processPayment(paymentData) {
    try {
      // Validate input data
      this.validatePaymentData(paymentData);

      const response = await fetch(`${this.baseURL}/process`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          amount: paymentData.amount,
          currency: paymentData.currency || 'AED',
          cardNumber: paymentData.cardNumber,
          expiryMonth: paymentData.expiryMonth,
          expiryYear: paymentData.expiryYear,
          cvv: paymentData.cvv
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
        console.log('Payment successful:', result.paymentId);
        return result;
      } else {
        console.error('Payment failed:', result.error);
        throw new Error(result.error);
      }
    } catch (error) {
      console.error('Payment processing error:', error);
      throw this.handleError(error);
    }
  }

  /**
   * Create a payment token
   * @param {Object} cardData - Card information
   * @returns {Promise<string>} Token ID
   */
  async createToken(cardData) {
    try {
      this.validateCardData(cardData);

      const response = await fetch(`${this.baseURL}/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          cardNumber: cardData.cardNumber,
          expiryMonth: cardData.expiryMonth,
          expiryYear: cardData.expiryYear,
          cvv: cardData.cvv
        })
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      if (result.success) {
        console.log('Token created:', result.tokenId);
        return result.tokenId;
      } else {
        console.error('Token creation failed:', result.error);
        throw new Error(result.error);
      }
    } catch (error) {
      console.error('Token creation error:', error);
      throw this.handleError(error);
    }
  }

  /**
   * Test signature generation (for debugging)
   * @returns {Promise<Object>} Signature test result
   */
  async testSignature() {
    try {
      const response = await fetch(`${this.baseURL}/signature-test`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({})
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Signature test error:', error);
      throw this.handleError(error);
    }
  }

  /**
   * Validate payment data
   * @param {Object} data - Payment data
   * @throws {Error} If validation fails
   */
  validatePaymentData(data) {
    const errors = [];
    
    if (!data.amount || parseFloat(data.amount) <= 0) {
      errors.push('Invalid amount');
    }
    
    if (!data.cardNumber || !/^\d{13,19}$/.test(data.cardNumber.replace(/\s/g, ''))) {
      errors.push('Invalid card number');
    }
    
    if (!data.expiryMonth || !data.expiryYear) {
      errors.push('Invalid expiry date');
    }
    
    if (!data.cvv || !/^\d{3,4}$/.test(data.cvv)) {
      errors.push('Invalid CVV');
    }
    
    if (errors.length > 0) {
      throw new Error(`Validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Validate card data for token creation
   * @param {Object} data - Card data
   * @throws {Error} If validation fails
   */
  validateCardData(data) {
    const errors = [];
    
    if (!data.cardNumber || !/^\d{13,19}$/.test(data.cardNumber.replace(/\s/g, ''))) {
      errors.push('Invalid card number');
    }
    
    if (!data.expiryMonth || !data.expiryYear) {
      errors.push('Invalid expiry date');
    }
    
    if (!data.cvv || !/^\d{3,4}$/.test(data.cvv)) {
      errors.push('Invalid CVV');
    }
    
    if (errors.length > 0) {
      throw new Error(`Validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Handle and format errors
   * @param {Error} error - Original error
   * @returns {Error} Formatted error
   */
  handleError(error) {
    if (error.message.includes('fetch failed')) {
      return new Error('Network error: Unable to connect to payment service');
    }
    
    if (error.message.includes('SSL')) {
      return new Error('Security error: SSL connection failed');
    }
    
    return error;
  }
}

// Export the service
export default CyberSourcePaymentService;

// Token creation function
async function createPaymentToken(cardData) {
  try {
    const response = await fetch('/api/payments/cybersource/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        cardNumber: cardData.cardNumber,
        expiryMonth: cardData.expiryMonth,
        expiryYear: cardData.expiryYear,
        cvv: cardData.cvv
      })
    });

    const result = await response.json();
    
    if (result.success) {
      console.log('Token created:', result.tokenId);
      return result.tokenId;
    } else {
      console.error('Token creation failed:', result.error);
      throw new Error(result.error);
    }
  } catch (error) {
    console.error('Token creation error:', error);
    throw error;
  }
}
```

### React Component Example

```jsx
import React, { useState } from 'react';
import CyberSourcePaymentService from './CyberSourcePaymentService';

const PaymentForm = () => {
  const [formData, setFormData] = useState({
    amount: '',
    cardNumber: '',
    expiryMonth: '',
    expiryYear: '',
    cvv: ''
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errors, setErrors] = useState({});

  const paymentService = new CyberSourcePaymentService();

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.amount || parseFloat(formData.amount) <= 0) {
      newErrors.amount = 'Please enter a valid amount';
    }
    
    if (!formData.cardNumber || !/^\d{13,19}$/.test(formData.cardNumber.replace(/\s/g, ''))) {
      newErrors.cardNumber = 'Please enter a valid card number';
    }
    
    if (!formData.expiryMonth || !formData.expiryYear) {
      newErrors.expiry = 'Please enter valid expiry date';
    }
    
    if (!formData.cvv || !/^\d{3,4}$/.test(formData.cvv)) {
      newErrors.cvv = 'Please enter a valid CVV';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    setResult(null);

    try {
      const data = await paymentService.processPayment({
        amount: formData.amount,
        currency: 'AED',
        cardNumber: formData.cardNumber,
        expiryMonth: formData.expiryMonth,
        expiryYear: formData.expiryYear,
        cvv: formData.cvv
      });
      
      setResult(data);
      
      // Reset form on success
      setFormData({
        amount: '',
        cardNumber: '',
        expiryMonth: '',
        expiryYear: '',
        cvv: ''
      });
      
    } catch (error) {
      setResult({ 
        success: false, 
        error: error.message 
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="payment-form">
      <h2>Payment Form</h2>
      <form onSubmit={handleSubmit} className="payment-form-container">
        <div className="form-group">
          <label htmlFor="amount">Amount (AED):</label>
          <input
            type="text"
            id="amount"
            name="amount"
            value={formData.amount}
            onChange={handleInputChange}
            placeholder="10.00"
            className={errors.amount ? 'error' : ''}
            required
          />
          {errors.amount && <span className="error-message">{errors.amount}</span>}
        </div>
        
        <div className="form-group">
          <label htmlFor="cardNumber">Card Number:</label>
          <input
            type="text"
            id="cardNumber"
            name="cardNumber"
            value={formData.cardNumber}
            onChange={handleInputChange}
            placeholder="4111111111111111"
            className={errors.cardNumber ? 'error' : ''}
            maxLength="19"
            required
          />
          {errors.cardNumber && <span className="error-message">{errors.cardNumber}</span>}
        </div>
        
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="expiryMonth">Expiry Month:</label>
            <select
              id="expiryMonth"
              name="expiryMonth"
              value={formData.expiryMonth}
              onChange={handleInputChange}
              className={errors.expiry ? 'error' : ''}
              required
            >
              <option value="">Month</option>
              {Array.from({length: 12}, (_, i) => (
                <option key={i+1} value={String(i+1).padStart(2, '0')}>
                  {String(i+1).padStart(2, '0')}
                </option>
              ))}
            </select>
          </div>
          
          <div className="form-group">
            <label htmlFor="expiryYear">Expiry Year:</label>
            <select
              id="expiryYear"
              name="expiryYear"
              value={formData.expiryYear}
              onChange={handleInputChange}
              className={errors.expiry ? 'error' : ''}
              required
            >
              <option value="">Year</option>
              {Array.from({length: 10}, (_, i) => {
                const year = new Date().getFullYear() + i;
                return (
                  <option key={year} value={year}>
                    {year}
                  </option>
                );
              })}
            </select>
          </div>
        </div>
        
        {errors.expiry && <span className="error-message">{errors.expiry}</span>}
        
        <div className="form-group">
          <label htmlFor="cvv">CVV:</label>
          <input
            type="text"
            id="cvv"
            name="cvv"
            value={formData.cvv}
            onChange={handleInputChange}
            placeholder="123"
            className={errors.cvv ? 'error' : ''}
            maxLength="4"
            required
          />
          {errors.cvv && <span className="error-message">{errors.cvv}</span>}
        </div>
        
        <button 
          type="submit" 
          disabled={loading}
          className="submit-button"
        >
          {loading ? 'Processing...' : 'Process Payment'}
        </button>
        
        {result && (
          <div className={`result-message ${result.success ? 'success' : 'error'}`}>
            {result.success ? (
              <div>
                <h3>Payment Successful!</h3>
                <p>Payment ID: {result.paymentId}</p>
                <p>Status: {result.status}</p>
              </div>
            ) : (
              <div>
                <h3>Payment Failed</h3>
                <p>Error: {result.error}</p>
              </div>
            )}
          </div>
        )}
      </form>
      
      <style jsx>{`
        .payment-form {
          max-width: 500px;
          margin: 0 auto;
          padding: 20px;
          font-family: Arial, sans-serif;
        }
        
        .payment-form-container {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }
        
        .form-group {
          display: flex;
          flex-direction: column;
          gap: 5px;
        }
        
        .form-row {
          display: flex;
          gap: 10px;
        }
        
        .form-row .form-group {
          flex: 1;
        }
        
        label {
          font-weight: bold;
          color: #333;
        }
        
        input, select {
          padding: 10px;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 16px;
        }
        
        input.error, select.error {
          border-color: #e74c3c;
        }
        
        .error-message {
          color: #e74c3c;
          font-size: 14px;
          margin-top: 5px;
        }
        
        .submit-button {
          background: #3498db;
          color: white;
          padding: 12px 24px;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          cursor: pointer;
          margin-top: 10px;
        }
        
        .submit-button:disabled {
          background: #bdc3c7;
          cursor: not-allowed;
        }
        
        .result-message {
          margin-top: 20px;
          padding: 15px;
          border-radius: 4px;
        }
        
        .result-message.success {
          background: #d4edda;
          border: 1px solid #c3e6cb;
          color: #155724;
        }
        
        .result-message.error {
          background: #f8d7da;
          border: 1px solid #f5c6cb;
          color: #721c24;
        }
        
        .result-message h3 {
          margin: 0 0 10px 0;
        }
        
        .result-message p {
          margin: 5px 0;
        }
      `}</style>
    </div>
  );
};

export default PaymentForm;
```

### Vue.js Integration

```vue
<template>
  <div>
    <form @submit.prevent="processPayment">
      <div>
        <label>Amount (AED):</label>
        <input v-model="formData.amount" type="text" placeholder="10.00" required />
      </div>
      
      <div>
        <label>Card Number:</label>
        <input v-model="formData.cardNumber" type="text" placeholder="4111111111111111" required />
      </div>
      
      <div>
        <label>Expiry Month:</label>
        <input v-model="formData.expiryMonth" type="text" placeholder="12" required />
      </div>
      
      <div>
        <label>Expiry Year:</label>
        <input v-model="formData.expiryYear" type="text" placeholder="2025" required />
      </div>
      
      <div>
        <label>CVV:</label>
        <input v-model="formData.cvv" type="text" placeholder="123" required />
      </div>
      
      <button type="submit" :disabled="loading">
        {{ loading ? 'Processing...' : 'Process Payment' }}
      </button>
      
      <div v-if="result" :class="result.success ? 'success' : 'error'">
        {{ result.success ? `Payment successful! ID: ${result.paymentId}` : `Payment failed: ${result.error}` }}
      </div>
    </form>
  </div>
</template>

<script>
export default {
  data() {
    return {
      formData: {
        amount: '',
        cardNumber: '',
        expiryMonth: '',
        expiryYear: '',
        cvv: ''
      },
      loading: false,
      result: null
    };
  },
  methods: {
    async processPayment() {
      this.loading = true;
      this.result = null;

      try {
        const response = await fetch('/api/payments/cybersource/process', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            amount: this.formData.amount,
            currency: 'AED',
            cardNumber: this.formData.cardNumber,
            expiryMonth: this.formData.expiryMonth,
            expiryYear: this.formData.expiryYear,
            cvv: this.formData.cvv
          })
        });

        const data = await response.json();
        this.result = data;
      } catch (error) {
        this.result = { success: false, error: error.message };
      } finally {
        this.loading = false;
      }
    }
  }
};
</script>
```

### Node.js/Express Integration

```javascript
const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

// Process payment from your own API
app.post('/api/process-payment', async (req, res) => {
  try {
    const { amount, cardNumber, expiryMonth, expiryYear, cvv } = req.body;

    const response = await axios.post('http://localhost:5000/api/payments/cybersource/process', {
      amount,
      currency: 'AED',
      cardNumber,
      expiryMonth,
      expiryYear,
      cvv
    });

    res.json(response.data);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.response?.data?.error || error.message
    });
  }
});

app.listen(3001, () => {
  console.log('Payment API running on port 3001');
});
```

## 🔧 cURL Examples

### Test Payment Processing

**Linux/Mac (curl):**
```bash
curl -X POST http://localhost:5000/api/payments/cybersource/process \
  -H "Content-Type: application/json" \
  -d '{
    "amount": "10.00",
    "currency": "AED",
    "cardNumber": "4111111111111111",
    "expiryMonth": "12",
    "expiryYear": "2025",
    "cvv": "123"
  }'
```

**Windows PowerShell:**
```powershell
$body = @{
    amount = "10.00"
    currency = "AED"
    cardNumber = "4111111111111111"
    expiryMonth = "12"
    expiryYear = "2025"
    cvv = "123"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:5000/api/payments/cybersource/process" -Method POST -ContentType "application/json" -Body $body
```

### Test Token Creation

**Linux/Mac (curl):**
```bash
curl -X POST http://localhost:5000/api/payments/cybersource/token \
  -H "Content-Type: application/json" \
  -d '{
    "cardNumber": "4111111111111111",
    "expiryMonth": "12",
    "expiryYear": "2025",
    "cvv": "123"
  }'
```

**Windows PowerShell:**
```powershell
$body = @{
    cardNumber = "4111111111111111"
    expiryMonth = "12"
    expiryYear = "2025"
    cvv = "123"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:5000/api/payments/cybersource/token" -Method POST -ContentType "application/json" -Body $body
```

### Test Signature Generation

**Linux/Mac (curl):**
```bash
curl -X POST http://localhost:5000/api/payments/cybersource/signature-test \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Windows PowerShell:**
```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/payments/cybersource/signature-test" -Method POST -ContentType "application/json" -Body "{}"
```

## ⚠️ Error Handling

### Common Error Responses

**Validation Errors:**
```json
{
  "success": false,
  "error": "amount, cardNumber, expiryMonth, expiryYear, and cvv are required"
}
```

**Payment Processing Errors:**
```json
{
  "success": false,
  "error": "Payment processing failed",
  "details": {
    "code": "INVALID_DATA",
    "message": "Missing required field: cardNumber"
  }
}
```

**Network/SSL Errors:**
```json
{
  "success": false,
  "error": "fetch failed",
  "details": {
    "cause": {
      "code": "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE"
    }
  }
}
```

### Troubleshooting Common Issues

#### 1. SSL Handshake Failure
**Error:** `ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE`

**Causes:**
- Invalid CyberSource credentials
- Network connectivity issues
- CyberSource service unavailable

**Solutions:**
```javascript
// Check if your environment variables are set
console.log('Merchant ID:', process.env.CYBERSOURCE_MERCHANT_ID);
console.log('Key ID:', process.env.CYBERSOURCE_KEY_ID);
console.log('Secret Key:', process.env.CYBERSOURCE_SECRET_KEY ? 'Set' : 'Not Set');
console.log('Environment:', process.env.CYBERSOURCE_RUN_ENVIRONMENT);
```

#### 2. Authentication Failed
**Error:** `Authentication Failed`

**Solutions:**
- Verify your CyberSource credentials in the EBC2 portal
- Check if your API key is active
- Ensure you're using the correct environment (test vs production)

#### 3. Invalid Data Errors
**Error:** `INVALID_DATA: Missing required field`

**Solutions:**
- Validate all required fields before sending
- Check data types (amounts as strings)
- Ensure card numbers are properly formatted

#### 4. Service Not Enabled
**Error:** `Service Not Enabled`

**Solutions:**
- Enable Simple Order API in EBC2 portal
- Enable Payment Tokenization Service
- Verify REST API access is enabled

### Error Handling Best Practices

```javascript
async function handlePayment(paymentData) {
  try {
    const response = await fetch('/api/payments/cybersource/process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(paymentData)
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    
    if (!result.success) {
      // Handle payment failure
      console.error('Payment failed:', result.error);
      throw new Error(result.error);
    }

    return result;
  } catch (error) {
    // Handle network or other errors
    console.error('Payment processing error:', error);
    throw error;
  }
}
```

## 🧪 Testing

### Test Card Numbers

| Card Type | Number | CVV | Expiry |
|-----------|--------|-----|--------|
| Visa | 4111111111111111 | Any 3 digits | Any future date |
| Mastercard | 5555555555554444 | Any 3 digits | Any future date |
| American Express | 378282246310005 | Any 4 digits | Any future date |
| Discover | 6011111111111117 | Any 3 digits | Any future date |

### Test Scenarios

1. **Successful Payment Test**
   ```json
   {
     "amount": "10.00",
     "currency": "AED",
     "cardNumber": "4111111111111111",
     "expiryMonth": "12",
     "expiryYear": "2025",
     "cvv": "123"
   }
   ```

2. **Declined Payment Test**
   ```json
   {
     "amount": "10.00",
     "currency": "AED",
     "cardNumber": "4000000000000002",
     "expiryMonth": "12",
     "expiryYear": "2025",
     "cvv": "123"
   }
   ```

## 🔒 Security Best Practices

### 1. Input Validation
```javascript
function validatePaymentData(data) {
  const errors = [];
  
  if (!data.amount || parseFloat(data.amount) <= 0) {
    errors.push('Invalid amount');
  }
  
  if (!data.cardNumber || !/^\d{13,19}$/.test(data.cardNumber.replace(/\s/g, ''))) {
    errors.push('Invalid card number');
  }
  
  if (!data.expiryMonth || !data.expiryYear) {
    errors.push('Invalid expiry date');
  }
  
  if (!data.cvv || !/^\d{3,4}$/.test(data.cvv)) {
    errors.push('Invalid CVV');
  }
  
  return errors;
}
```

### 2. Rate Limiting
```javascript
const rateLimit = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const lastRequest = rateLimit.get(ip);
  
  if (lastRequest && now - lastRequest < 1000) {
    throw new Error('Rate limit exceeded');
  }
  
  rateLimit.set(ip, now);
}
```

### 3. Secure Data Handling
- Never store card details in your database
- Use HTTPS in production
- Implement proper logging without sensitive data
- Validate all input data
- Use environment variables for credentials

## 📞 Support

For issues or questions:

1. Check the [CyberSource Setup Guide](./CYBERSOURCE_SETUP.md)
2. Review the [CyberSource Node.js Guide](./CYBERSOURCE_NODEJS_GUIDE.md)
3. Test with the signature test endpoint
4. Check your environment variables
5. Verify your CyberSource account settings

## 🚀 Quick Start Implementation

### Step 1: Set Up Environment Variables
Create a `.env` file in your project root:
```bash
CYBERSOURCE_MERCHANT_ID=your_merchant_id
CYBERSOURCE_KEY_ID=your_key_id
CYBERSOURCE_SECRET_KEY=your_secret_key
CYBERSOURCE_RUN_ENVIRONMENT=apitest.cybersource.com
```

### Step 2: Create Payment Service
Create `src/services/CyberSourcePaymentService.js`:
```javascript
// Copy the complete CyberSourcePaymentService class from above
import CyberSourcePaymentService from './CyberSourcePaymentService';

const paymentService = new CyberSourcePaymentService();
export default paymentService;
```

### Step 3: Create Payment Component
Create `src/components/PaymentForm.jsx`:
```jsx
// Copy the complete PaymentForm component from above
import PaymentForm from './PaymentForm';
export default PaymentForm;
```

### Step 4: Test the Implementation
```javascript
// Test with signature endpoint first
const testSignature = async () => {
  try {
    const result = await paymentService.testSignature();
    console.log('Signature test successful:', result);
  } catch (error) {
    console.error('Signature test failed:', error);
  }
};

// Test with payment processing
const testPayment = async () => {
  try {
    const result = await paymentService.processPayment({
      amount: '10.00',
      currency: 'AED',
      cardNumber: '4111111111111111',
      expiryMonth: '12',
      expiryYear: '2025',
      cvv: '123'
    });
    console.log('Payment successful:', result);
  } catch (error) {
    console.error('Payment failed:', error);
  }
};
```

### Step 5: Integration Checklist

- [ ] Set up environment variables
- [ ] Test with signature test endpoint
- [ ] Try payment processing with test card
- [ ] Implement error handling
- [ ] Add input validation
- [ ] Test with different card types
- [ ] Implement rate limiting (optional)
- [ ] Add logging for debugging
- [ ] Test SSL connection
- [ ] Verify CyberSource credentials
- [ ] Test error scenarios
- [ ] Implement retry logic for network failures

---

**Note:** This implementation follows the direct HTTP approach recommended in the CyberSource guide for better control and debugging capabilities.

# CyberSource Payment Gateway Setup

This document provides setup instructions for the CyberSource payment gateway integration.

## Environment Variables

Add the following environment variables to your `.env` file:

```bash
# CyberSource Configuration
CYBERSOURCE_MERCHANT_ID=your_merchant_id
CYBERSOURCE_KEY_ID=your_key_id
CYBERSOURCE_SECRET_KEY=your_secret_key
CYBERSOURCE_RUN_ENVIRONMENT=apitest.cybersource.com

# Legacy CyberSource Configuration (for backward compatibility)
CYBS_MERCHANT_ID=your_merchant_id
CYBS_API_KEY_ID=your_key_id
CYBS_API_SECRET_KEY=your_secret_key
CYBS_HOST=apitest.cybersource.com
```

## API Endpoints

### 1. Payment Processing
**POST** `/api/payments/cybersource/process`

Process a direct payment with card details.

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

**Response:**
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

### 2. Token Creation
**POST** `/api/payments/cybersource/token`

Create a payment token for future use.

**Request Body:**
```json
{
  "cardNumber": "4111111111111111",
  "expiryMonth": "12",
  "expiryYear": "2025",
  "cvv": "123"
}
```

### 3. Signature Test (Debug)
**POST** `/api/payments/cybersource/signature-test`

Test signature generation for debugging purposes.

## Test Card Numbers

Use these test card numbers for testing (they won't charge real money):

| Card Type | Number | CVV | Expiry |
|-----------|--------|-----|--------|
| Visa | 4111111111111111 | Any 3 digits | Any future date |
| Mastercard | 5555555555554444 | Any 3 digits | Any future date |
| American Express | 378282246310005 | Any 4 digits | Any future date |
| Discover | 6011111111111117 | Any 3 digits | Any future date |

## Testing

### Test Payment Request
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

### Test Token Creation
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

### Test Signature Generation
```bash
curl -X POST http://localhost:5000/api/payments/cybersource/signature-test \
  -H "Content-Type: application/json" \
  -d '{}'
```

## Expected Success Response
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

## Troubleshooting

### Common Errors

1. **"INVALID_DATA" Error**
   - Verify JSON payload structure matches CyberSource requirements
   - Ensure all required fields are present
   - Check data types (amounts as strings, dates as proper format)

2. **"Authentication Failed" Error**
   - Verify API credentials are correct
   - Check if secret key needs base64 decoding
   - Ensure API key is active in EBC2 portal
   - Verify signature string order and format

3. **"Service Not Enabled" Error**
   - Enable Simple Order API in EBC2 portal
   - Enable Payment Tokenization Service
   - Verify REST API access is enabled

4. **"Invalid Merchant" Error**
   - Verify merchant ID is correct
   - Check account status in EBC2 portal
   - Ensure test account is active

## Security Best Practices

1. **Environment Variables**: Never commit credentials to version control
2. **Input Validation**: Validate card number format and expiry dates
3. **Error Handling**: Log errors securely without exposing sensitive data
4. **PCI Compliance**: Never store card details in your database
5. **Rate Limiting**: Implement rate limiting for payment endpoints

## Account Setup

1. Visit [CyberSource Developer Portal](https://developer.cybersource.com/)
2. Sign up for a developer account
3. Complete business verification process
4. Log into [EBC2 Test Environment](https://ebc2test.cybersource.com/ebc2)
5. Navigate to your merchant profile and note your **Merchant ID**
6. Go to **Security** → **API Keys** and generate new API key
7. Select **Sandbox** environment and **Payment Processing** permissions
8. Copy your **Key ID** and **Secret Key**
9. Enable required services: Simple Order API, Payment Tokenization Service, REST API access

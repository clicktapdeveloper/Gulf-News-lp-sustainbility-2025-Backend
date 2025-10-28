# CyberSource Hosted Checkout Setup Guide

This guide explains how to configure and use the CyberSource Hosted Checkout integration for nomination payments.

## Environment Variables

Add the following environment variables to your `.env` file:

```bash
# CyberSource Hosted Checkout Credentials
CYBERSOURCE_ACCESS_KEY=f562c36a69bc3e86ac7453fd2e4eff6b
CYBERSOURCE_PROFILE_ID=1E54EA09-4412-4AC2-BF88-A2ACD2E340F3
CYBERSOURCE_SECRET_KEY=562810436f684da8874c503e8c446beb6fa1f8b1e6734d2d84b83651327fcd0a98b372e5493a4115afb34704ccf74a039724f37eb30341ef9a370b2140356d6870b2cac7fb4d49ac9e2fe47fbe4461d285c033dc8fe34c94bba6d9c3f796885903c69346c3244b9b988eb6069c06ac0aa04bb4cbe486434296ed9ae17348c7ba

# Environment (test or production)
CYBERSOURCE_ENVIRONMENT=test
```

## API Endpoints

### 1. Create Nomination Payment Request

**POST** `/api/payments/cybersource/nomination-payment`

Creates a payment request and redirects to CyberSource Hosted Checkout.

#### Request Body:
```json
{
  "amount": 150.00,
  "currency": "AED",
  "customerEmail": "customer@example.com",
  "customerFirstName": "John",
  "customerLastName": "Doe",
  "customerAddress": "123 Main Street",
  "customerCity": "Dubai",
  "customerCountry": "AE",
  "nominationData": {
    "category": "Innovation",
    "description": "Nomination description"
  }
}
```

#### Response:
Returns an HTML form that automatically redirects to CyberSource payment page.

### 2. Payment Return Handler

**POST** `/api/payments/cybersource/return`

Handles the payment result from CyberSource.

#### CyberSource POST Data:
The endpoint receives the complete payment response from CyberSource including:
- `transaction_id`: Unique transaction identifier
- `decision`: Payment decision (ACCEPT/DECLINE/ERROR)
- `reason_code`: Reason for the decision
- `auth_amount`: Authorized amount
- `signature`: Digital signature for verification

#### Response:
- **Success**: Redirects to `/nomination/success?transaction_id=...`
- **Failure**: Redirects to `/nomination/error?reason=...&message=...`

### 3. Payment Cancel Handler

**POST** `/api/payments/cybersource/cancel`

Handles payment cancellation by user.

#### Response:
Redirects to `/nomination/cancelled`

## Integration Flow

### Frontend Integration

```javascript
// Submit nomination form with payment
async function submitNomination(nominationData) {
  const response = await fetch('/api/payments/cybersource/nomination-payment', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      amount: 150.00,
      currency: 'AED',
      customerEmail: nominationData.email,
      customerFirstName: nominationData.firstName,
      customerLastName: nominationData.lastName,
      customerAddress: nominationData.address,
      customerCity: nominationData.city,
      customerCountry: nominationData.country,
      nominationData: nominationData
    })
  });

  // The response is HTML that will redirect to CyberSource
  const html = await response.text();
  document.body.innerHTML = html;
}
```

### CyberSource Configuration

1. **Return URL**: Set to `https://yourdomain.com/api/payments/cybersource/return`
2. **Cancel URL**: Set to `https://yourdomain.com/api/payments/cybersource/cancel`
3. **Receipt URL**: Optional, can be the same as return URL

## Payment Flow

1. **User submits nomination form** → Frontend calls nomination payment endpoint
2. **Server creates payment request** → Generates signed parameters for CyberSource
3. **User redirected to CyberSource** → Secure payment page hosted by CyberSource
4. **User completes payment** → Card details processed by CyberSource
5. **CyberSource returns result** → POST to return URL with payment details
6. **Server processes result** → Verifies signature and saves nomination
7. **User redirected to result page** → Success, error, or cancelled page

## Security Features

### Digital Signature Verification
- All CyberSource responses are verified using HMAC-SHA256
- Prevents tampering with payment results
- Ensures data integrity

### Secure Data Handling
- No card data touches your servers
- All sensitive payment information handled by CyberSource
- PCI DSS compliance maintained

## Error Handling

### Common Error Scenarios

1. **Configuration Errors**
   - Missing environment variables
   - Invalid credentials
   - Wrong environment setting

2. **Payment Errors**
   - Card declined
   - Insufficient funds
   - Invalid card details
   - Network timeouts

3. **Processing Errors**
   - Invalid signature
   - Database connection issues
   - Email sending failures

### Error Response Format

```json
{
  "success": false,
  "error": "Error description",
  "details": "Additional error information",
  "missingVariables": ["VAR1", "VAR2"] // For config errors
}
```

## Testing

### Test Card Numbers (Test Environment)

- **Visa**: 4111111111111111
- **Mastercard**: 5555555555554444
- **American Express**: 378282246310005

### Test Scenarios

1. **Successful Payment**
   - Use any test card number
   - Enter any future expiry date
   - Use any CVV

2. **Declined Payment**
   - Use card number: 4000000000000002
   - This will simulate a declined transaction

3. **Cancelled Payment**
   - Start payment process
   - Close browser or navigate away
   - Should trigger cancel URL

## Production Deployment

### Environment Variables
```bash
# Production CyberSource Credentials
CYBERSOURCE_ACCESS_KEY=your_production_access_key
CYBERSOURCE_PROFILE_ID=your_production_profile_id
CYBERSOURCE_SECRET_KEY=your_production_secret_key
CYBERSOURCE_ENVIRONMENT=production
```

### Security Considerations

1. **HTTPS Required**
   - All endpoints must use HTTPS in production
   - CyberSource will reject HTTP requests

2. **Environment Variables**
   - Store credentials securely
   - Never commit to version control
   - Use environment-specific values

3. **Monitoring**
   - Log all payment attempts
   - Monitor for failed payments
   - Set up alerts for processing errors

## Troubleshooting

### Common Issues

1. **"Invalid signature" errors**
   - Check secret key configuration
   - Verify environment variables
   - Ensure proper encoding

2. **Redirect loops**
   - Verify return/cancel URLs
   - Check CORS settings
   - Ensure proper response handling

3. **Payment not processing**
   - Check CyberSource account status
   - Verify profile configuration
   - Review transaction logs

### Debug Mode

Enable detailed logging by setting:
```bash
NODE_ENV=development
```

This will log all CyberSource requests and responses for debugging.

## Support

For CyberSource-specific issues:
- Check CyberSource documentation
- Contact CyberSource support
- Review transaction logs in CyberSource portal

For integration issues:
- Check server logs
- Verify environment configuration
- Test with sample data


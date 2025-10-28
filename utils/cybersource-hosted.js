import crypto from 'crypto';
import { randomUUID } from 'crypto';

// CyberSource Hosted Checkout Integration
// This module handles the complete payment flow using CyberSource Hosted Checkout

/**
 * @typedef {Object} CyberSourceParams
 * @property {string} access_key
 * @property {string} profile_id
 * @property {string} transaction_uuid
 * @property {string} signed_field_names
 * @property {string} unsigned_field_names
 * @property {string} signed_date_time
 * @property {string} locale
 * @property {string} transaction_type
 * @property {string} reference_number
 * @property {string} amount
 * @property {string} currency
 * @property {string} bill_to_email
 * @property {string} bill_to_forename
 * @property {string} bill_to_surname
 * @property {string} bill_to_address_line1
 * @property {string} bill_to_address_city
 * @property {string} bill_to_address_country
 * @property {string} [signature]
 */

/**
 * @typedef {Object} PaymentRequest
 * @property {string} customerEmail
 * @property {string} [customerFirstName]
 * @property {string} [customerLastName]
 * @property {string} [customerAddress]
 * @property {string} [customerCity]
 * @property {string} [customerCountry]
 * @property {number} amount
 * @property {string} [currency]
 * @property {Object} [nominationData]
 */

/**
 * Get CyberSource URL based on environment
 */
export function getCyberSourceUrl() {
  return process.env.CYBERSOURCE_ENVIRONMENT === 'production' 
    ? 'https://secureacceptance.cybersource.com/pay' 
    : 'https://testsecureacceptance.cybersource.com/pay';
}

/**
 * Generate signature for CyberSource request
 * @param {CyberSourceParams} params - The payment parameters
 * @returns {string} The generated signature
 */
export function generateSignature(params) {
  const secretKey = process.env.CYBERSOURCE_SECRET_KEY;
  
  if (!secretKey) {
    throw new Error('CYBERSOURCE_SECRET_KEY environment variable is required');
  }

  const signedFieldNames = params.signed_field_names.split(',');
  const dataToSign = signedFieldNames
    .map(field => `${field}=${params[field] || ''}`)
    .join(',');
    
  return crypto
    .createHmac('sha256', secretKey)
    .update(dataToSign)
    .digest('base64');
}

/**
 * Create payment parameters for CyberSource
 * @param {PaymentRequest} request - The payment request data
 * @returns {CyberSourceParams} The CyberSource payment parameters
 */
export function createPaymentParams(request) {
  const timestamp = new Date().toISOString().replace(/\.\d{3}/, '');
  const transactionUuid = randomUUID();
  const referenceNumber = `NOMINATION-${Date.now()}`;
  
  // Get base URL for return/cancel URLs
  const baseUrl = process.env.BACKEND_URL || 'http://localhost:5000';
  const returnUrl = `${baseUrl}/api/payments/cybersource/return`;
  const cancelUrl = `${baseUrl}/api/payments/cybersource/cancel`;
  
  const params = {
    access_key: process.env.CYBERSOURCE_ACCESS_KEY,
    profile_id: process.env.CYBERSOURCE_PROFILE_ID,
    transaction_uuid: transactionUuid,
    signed_field_names: 'access_key,profile_id,transaction_uuid,unsigned_field_names,signed_field_names,signed_date_time,locale,transaction_type,reference_number,amount,currency,override_custom_receipt_page,override_custom_cancel_page,bill_to_email,bill_to_forename,bill_to_surname,bill_to_address_line1,bill_to_address_city,bill_to_address_country',
    unsigned_field_names: '',
    signed_date_time: timestamp,
    locale: 'en',
    transaction_type: 'sale',
    reference_number: referenceNumber,
    amount: request.amount.toFixed(2),
    currency: request.currency || 'AED',
    override_custom_receipt_page: returnUrl,
    override_custom_cancel_page: cancelUrl,
    bill_to_email: request.customerEmail,
    bill_to_forename: request.customerFirstName || 'Nominee',
    bill_to_surname: request.customerLastName || 'User',
    bill_to_address_line1: request.customerAddress || 'Dubai, UAE',
    bill_to_address_city: request.customerCity || 'Dubai',
    bill_to_address_country: request.customerCountry || 'AE',
  };

  // Generate signature
  params.signature = generateSignature(params);
  
  return params;
}

/**
 * Verify CyberSource response signature
 * @param {Object} responseData - The response data from CyberSource
 * @returns {boolean} Whether the signature is valid
 */
export function verifyCyberSourceSignature(responseData) {
  try {
    const secretKey = process.env.CYBERSOURCE_SECRET_KEY;
    
    if (!secretKey) {
      console.error('CYBERSOURCE_SECRET_KEY environment variable is required');
      return false;
    }

    const signedFieldNames = responseData.signed_field_names.split(',');
    const dataToSign = signedFieldNames
      .map(field => `${field}=${responseData[field] || ''}`)
      .join(',');
      
    const expectedSignature = crypto
      .createHmac('sha256', secretKey)
      .update(dataToSign)
      .digest('base64');
      
    return expectedSignature === responseData.signature;
  } catch (error) {
    console.error('Error verifying CyberSource signature:', error);
    return false;
  }
}

/**
 * Process CyberSource payment response
 * @param {Object} responseData - The response data from CyberSource
 * @returns {Object} Processed payment result
 */
export function processPaymentResponse(responseData) {
  const isValidSignature = verifyCyberSourceSignature(responseData);
  
  if (!isValidSignature) {
    throw new Error('Invalid signature in CyberSource response');
  }

  const result = {
    transactionId: responseData.transaction_id,
    decision: responseData.decision,
    reasonCode: responseData.reason_code,
    message: responseData.message,
    amount: responseData.auth_amount || responseData.req_amount,
    currency: responseData.req_currency,
    cardType: responseData.card_type_name,
    authCode: responseData.auth_code,
    authTime: responseData.auth_time,
    billToEmail: responseData.req_bill_to_email,
    billToForename: responseData.req_bill_to_forename,
    billToSurname: responseData.req_bill_to_surname,
    referenceNumber: responseData.req_reference_number,
    transactionUuid: responseData.req_transaction_uuid,
    isSuccess: responseData.decision === 'ACCEPT',
    responseData: responseData
  };

  return result;
}

/**
 * Create HTML form for CyberSource redirect
 * @param {CyberSourceParams} params - The payment parameters
 * @returns {string} HTML form for redirect
 */
export function createCyberSourceForm(params) {
  const formFields = Object.entries(params)
    .filter(([key, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `<input type="hidden" name="${key}" value="${value}" />`)
    .join('\n');

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Redirecting to Payment...</title>
      <style>
        body { 
          font-family: Arial, sans-serif; 
          text-align: center; 
          padding: 50px; 
          background-color: #EBF1E7;
        }
        .container {
          max-width: 500px;
          margin: 0 auto;
          background: white;
          padding: 40px;
          border-radius: 16px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .spinner {
          border: 4px solid #DBE2CD;
          border-top: 4px solid #224442;
          border-radius: 50%;
          width: 40px;
          height: 40px;
          animation: spin 1s linear infinite;
          margin: 20px auto;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        h2 {
          color: #224442;
          margin-bottom: 20px;
        }
        p {
          color: #000000;
          margin-bottom: 10px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>🔄 Redirecting to Payment</h2>
        <div class="spinner"></div>
        <p>Please wait while we redirect you to our secure payment processor...</p>
        <p><small>If you are not redirected automatically, please click the button below.</small></p>
        
        <form id="cybersourceForm" action="${getCyberSourceUrl()}" method="POST">
          ${formFields}
          <button type="submit" style="
            background: linear-gradient(135deg, #224442 0%, #DBE2CD 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
          ">
            Continue to Payment
          </button>
        </form>
      </div>
      
      <script>
        // Auto-submit form after 2 seconds
        setTimeout(function() {
          document.getElementById('cybersourceForm').submit();
        }, 2000);
      </script>
    </body>
    </html>
  `;
}

/**
 * Validate required environment variables
 * @returns {Object} Configuration validation result
 */
export function validateCyberSourceConfig() {
  const requiredVars = [
    'CYBERSOURCE_ACCESS_KEY',
    'CYBERSOURCE_PROFILE_ID', 
    'CYBERSOURCE_SECRET_KEY',
    'CYBERSOURCE_ENVIRONMENT'
  ];
  
  const missingVars = requiredVars.filter(varName => !process.env[varName]);
  
  return {
    isValid: missingVars.length === 0,
    missingVars
  };
}

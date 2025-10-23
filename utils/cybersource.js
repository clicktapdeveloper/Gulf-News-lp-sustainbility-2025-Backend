import crypto from 'crypto';

/**
 * CyberSource Configuration Object
 * @typedef {Object} CyberSourceConfig
 * @property {string} merchantID - CyberSource merchant ID
 * @property {string} keyId - API key ID
 * @property {string} secretKey - API secret key
 * @property {string} runEnvironment - API environment URL
 */

/**
 * Payment Request Object
 * @typedef {Object} PaymentRequest
 * @property {string} amount - Payment amount
 * @property {string} currency - Payment currency
 * @property {string} cardNumber - Card number
 * @property {string} expiryMonth - Card expiry month
 * @property {string} expiryYear - Card expiry year
 * @property {string} cvv - Card CVV
 */

/**
 * Payment Response Object
 * @typedef {Object} PaymentResponse
 * @property {string} id - Payment ID
 * @property {string} status - Payment status
 * @property {Object} [statusInformation] - Status information
 * @property {string} [statusInformation.reason] - Status reason
 * @property {string} [statusInformation.message] - Status message
 * @property {Object} [processorInformation] - Processor information
 * @property {string} [processorInformation.responseCode] - Response code
 * @property {string} [processorInformation.responseMessage] - Response message
 */

function getConfig() {
  const merchantId = process.env.CYBERSOURCE_MERCHANT_ID || process.env.CYBS_MERCHANT_ID || '';
  const keyId = process.env.CYBERSOURCE_KEY_ID || process.env.CYBS_API_KEY_ID || '';
  const secretKey = process.env.CYBERSOURCE_SECRET_KEY || process.env.CYBS_API_SECRET_KEY || '';
  // Fix common environment URL issues
  // let runEnvironment = process.env.CYBERSOURCE_RUN_ENVIRONMENT || process.env.CYBS_HOST || 'apitest.cybersource.com';
  let runEnvironment = process.env.CYBERSOURCE_RUN_ENVIRONMENT || 'apitest.cybersource.com';
  
  // Fix common typos in environment URLs
  if (runEnvironment.includes('matest')) {
    runEnvironment = 'apitest.cybersource.com';
    console.warn('Fixed incorrect CyberSource environment URL from', process.env.CYBS_HOST, 'to', runEnvironment);
  }

  // Debug logging to help identify configuration issues
  console.log('CyberSource Config Debug:', {
    merchantID: merchantId ? `${merchantId.substring(0, 4)}...` : 'NOT_SET',
    keyId: keyId ? `${keyId.substring(0, 4)}...` : 'NOT_SET',
    secretKey: secretKey ? 'SET' : 'NOT_SET',
    runEnvironment: runEnvironment
  });

  // Validate required configuration
  if (!merchantId) {
    throw new Error('CYBERSOURCE_MERCHANT_ID is required');
  }
  if (!keyId) {
    throw new Error('CYBERSOURCE_KEY_ID is required');
  }
  if (!secretKey) {
    throw new Error('CYBERSOURCE_SECRET_KEY is required');
  }

  return {
    merchantID: merchantId,
    keyId: keyId,
    secretKey: secretKey,
    runEnvironment: runEnvironment
  };
}

class CyberSourceClient {
  /**
   * Create a new CyberSource client
   * @param {CyberSourceConfig} config - Configuration object
   */
  constructor(config) {
    this.config = config;
  }

  /**
   * Generate digest for request payload
   * @param {string} payload - Request payload
   * @returns {string} Digest string
   */
  generateDigest(payload) {
    const hash = crypto.createHash('sha256').update(payload).digest('base64');
    return `SHA-256=${hash}`;
  }

  /**
   * Generate signature for request
   * @param {string} method - HTTP method
   * @param {string} resourcePath - API resource path
   * @param {string} payload - Request payload
   * @param {string} timestamp - Request timestamp
   * @param {string} digest - Request digest
   * @returns {string} Signature string
   */
  generateSignature(method, resourcePath, payload, timestamp, digest) {
    const signatureString = `host: ${this.config.runEnvironment}\n` +
                           `date: ${timestamp}\n` +
                           `(request-target): ${method.toLowerCase()} ${resourcePath}\n` +
                           `digest: ${digest}\n` +
                           `v-c-merchant-id: ${this.config.merchantID}`;

    // Try both raw secret key and base64 decoded secret key
    let signature;
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

  /**
   * Make HTTP request to CyberSource API
   * @param {string} method - HTTP method
   * @param {string} resourcePath - API resource path
   * @param {any} [payload] - Request payload
   * @returns {Promise<any>} API response
   */
  async makeRequest(method, resourcePath, payload) {
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

    console.log('CyberSource Request Debug:', {
      url,
      method,
      resourcePath,
      headers: {
        ...headers,
        'v-c-merchant-id': `${this.config.merchantID.substring(0, 4)}...`,
        'Signature': `keyid="${this.config.keyId.substring(0, 4)}...", algorithm="HmacSHA256", headers="host date (request-target) digest v-c-merchant-id", signature="${signature.substring(0, 10)}..."`
      },
      payloadSize: payloadString.length
    });

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: payloadString || undefined
      });

      console.log('CyberSource Response Debug:', {
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries())
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('CyberSource API Error:', {
          status: response.status,
          statusText: response.statusText,
          errorText
        });
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      const result = await response.json();
      console.log('CyberSource Success:', {
        id: result.id,
        status: result.status
      });
      
      return result;
    } catch (error) {
      console.error('CyberSource Request Failed:', {
        url,
        method,
        error: error.message,
        cause: error.cause?.message || error.cause?.code || 'Unknown'
      });
      throw error;
    }
  }

  /**
   * Create a payment
   * @param {PaymentRequest} paymentData - Payment data
   * @returns {Promise<PaymentResponse>} Payment response
   */
  async createPayment(paymentData) {
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

  /**
   * Create a payment token
   * @param {PaymentRequest} paymentData - Payment data
   * @returns {Promise<PaymentResponse>} Token response
   */
  async createToken(paymentData) {
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

  // Legacy method for backward compatibility
  async createCardPayment({ amount, currency = 'AED', transientToken, referenceId, customerEmail }) {
    // For backward compatibility, we'll use the createPayment method
    // but this requires card details instead of transientToken
    // You may need to modify your frontend to send card details instead of transientToken
    
    if (transientToken) {
      throw new Error('Transient token payments not supported with direct HTTP implementation. Please use card details instead.');
    }
    
    // This is a placeholder - you'll need to modify your frontend to send card details
    throw new Error('Please update your frontend to send card details (cardNumber, expiryMonth, expiryYear, cvv) instead of transientToken');
  }
}

export function createPaymentsClient() {
  const configObject = getConfig();
  return new CyberSourceClient(configObject);
}

export async function createCardPayment({ amount, currency = 'AED', transientToken, referenceId, customerEmail }) {
  const client = createPaymentsClient();
  return await client.createCardPayment({ amount, currency, transientToken, referenceId, customerEmail });
}

export { CyberSourceClient };
export default CyberSourceClient;






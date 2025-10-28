// Test script for nomination endpoints
import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:5000';

// Test data for initial nomination submission
const testNominationData = {
  firstName: "John",
  lastName: "Doe",
  email: "john.doe@example.com",
  companyName: "Example Corp",
  designation: "CEO",
  phone: "+971501234567",
  tradeLicense: "TL123456",
  supportingDocument: "https://example.com/doc1.pdf,https://example.com/doc2.pdf",
  message: "Optional message",
  status: "unpaid",
  submittedAt: "2025-01-27T10:30:00.000Z"
};

// Test data for payment update
const testPaymentData = {
  status: "paid",
  paymentAmount: 199,
  paymentCurrency: "AED",
  paymentDate: "2025-01-27T10:35:00.000Z",
  paymentReference: "txn_1738068900000_abc123def",
  paymentStatus: "completed",
  paymentMethod: "cybersource_hosted",
  cybersourceTransactionId: "txn_1738068900000_abc123def",
  authCode: "831000",
  authTime: "2025-01-27T10:35:00Z",
  cardType: "Visa",
  paidAt: "2025-01-27T10:35:00.000Z"
};

async function testCreateNomination() {
  console.log('🧪 Testing POST /api/nominations...');
  
  try {
    const response = await fetch(`${BASE_URL}/api/nominations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testNominationData)
    });

    const result = await response.json();
    
    if (response.ok) {
      console.log('✅ Nomination created successfully:', result);
      return result._id;
    } else {
      console.log('❌ Failed to create nomination:', result);
      return null;
    }
  } catch (error) {
    console.log('❌ Error testing nomination creation:', error.message);
    return null;
  }
}

async function testUpdatePayment(nominationId) {
  if (!nominationId) {
    console.log('❌ No nomination ID provided for payment update test');
    return;
  }

  console.log('🧪 Testing PATCH /api/nominations/:nominationId/payment...');
  
  try {
    const response = await fetch(`${BASE_URL}/api/nominations/${nominationId}/payment`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testPaymentData)
    });

    const result = await response.json();
    
    if (response.ok) {
      console.log('✅ Payment updated successfully:', result);
    } else {
      console.log('❌ Failed to update payment:', result);
    }
  } catch (error) {
    console.log('❌ Error testing payment update:', error.message);
  }
}

async function testValidationErrors() {
  console.log('🧪 Testing validation errors...');
  
  // Test missing required fields
  const invalidData = {
    firstName: "John",
    // Missing lastName, email, etc.
  };

  try {
    const response = await fetch(`${BASE_URL}/api/nominations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(invalidData)
    });

    const result = await response.json();
    
    if (!response.ok) {
      console.log('✅ Validation error caught correctly:', result);
    } else {
      console.log('❌ Validation should have failed:', result);
    }
  } catch (error) {
    console.log('❌ Error testing validation:', error.message);
  }
}

async function runTests() {
  console.log('🚀 Starting nomination endpoint tests...\n');
  
  // Test validation errors first
  await testValidationErrors();
  console.log('');
  
  // Test successful nomination creation
  const nominationId = await testCreateNomination();
  console.log('');
  
  // Test payment update
  await testUpdatePayment(nominationId);
  console.log('');
  
  console.log('🏁 Tests completed!');
}

// Run tests
runTests().catch(console.error);

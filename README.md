# Event Ticketing Backend Server

A standalone Express.js backend server for the Event Ticketing application, separated from the Next.js frontend for better maintainability and scalability.

## 🚀 Features

- **Stripe Payment Integration** - Checkout sessions for event tickets and nominations
- **MongoDB Database** - Store bookings, nominations, and attendee data
- **Email Notifications** - Send confirmation emails with QR codes
- **QR Code Generation** - Generate unique QR codes for each ticket
- **RESTful API** - Well-structured API endpoints
- **CORS Support** - Secure cross-origin requests from frontend

## 📋 Prerequisites

- Node.js (v18 or higher)
- MongoDB (local or MongoDB Atlas)
- Stripe Account
 - Stripe Account (for existing flow) or CyberSource Account (if using CyberSource)
- Gmail Account (for email notifications)

## 🛠️ Installation

1. **Navigate to the server directory:**
   ```bash
   cd server
   ```

2. **Copy the environment example file:**
   ```bash
   cp .env.example .env
   ```

3. **Configure environment variables in `.env`:**
   - Add your MongoDB connection string
   - Add your Stripe secret key
   - Add your Gmail credentials (use App Password for Gmail)
   - Configure event details
   - Set admin email for notifications

4. **Install dependencies from the root directory:**
   ```bash
   cd ..
   npm install
   ```

## 🏃 Running the Server

### Development Mode (with auto-reload):
```bash
npm run server:dev
```

### Production Mode:
```bash
npm run server
```

The server will start on `http://localhost:5000` (or the PORT specified in your .env file).

## 📡 API Endpoints

### Health Check
- **GET** `/api/health` - Check if the server is running

### Checkout & Payments
- **POST** `/api/checkout_sessions` - Create Stripe checkout session
  - Body: `{ type, attendees, ticketPrice, eventName, eventDate, eventLocation }` (for tickets)
  - Body: `{ type: 'nomination', amount, nominationData }` (for nominations)
 
### CyberSource Payments (New)
- **POST** `/api/payments/cybersource/charge` - Create CyberSource card payment from Flex token
  - Body: `{ amount, currency, transientToken, referenceId, customerEmail }`

### Attendee Registration
- **POST** `/api/register-attendee` - Register a new attendee
  - Body: `{ firstName, lastName, email, phone, company, position, industry, interests, dietaryRequirements }`

### Sponsorship
- **POST** `/api/sponsorship` - Submit sponsorship request
  - Body: `{ companyName, contactPerson, email, phone, website, sponsorshipLevel, budget, message }`

### Payment Verification
- **GET** `/api/verify-payment?session_id=xxx` - Verify Stripe payment and send tickets
  - Query param: `session_id` - Stripe checkout session ID

## 🔐 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `MONGODB_URI` | MongoDB connection string | ✅ |
| `STRIPE_SECRET_KEY` | Stripe secret key | ✅ |
| `CYBS_MERCHANT_ID` | CyberSource merchant identifier | ❌ |
| `CYBS_API_KEY_ID` | CyberSource REST API key ID | ❌ |
| `CYBS_API_SECRET_KEY` | CyberSource REST API secret | ❌ |
| `CYBS_FLEX_KEY_ID` | CyberSource Flex Microform key ID | ❌ |
| `CYBS_FLEX_PUBLIC_KEY` | CyberSource Flex Microform public key JSON | ❌ |
| `CYBS_ENV` | `test` or `production` | ❌ |
| `CYBS_HOST` | `api-matest.cybersource.com` or `api.cybersource.com` | ❌ |
| `EMAIL_USER` | Gmail email address | ✅ |
| `EMAIL_PASS` | Gmail app password | ✅ |
| `EMAIL_FROM` | Email sender name and address | ❌ |
| `ADMIN_EMAIL` | Admin email for notifications | ❌ |
| `PORT` | Server port (default: 5000) | ❌ |
| `FRONTEND_URL` | Frontend URL for CORS (default: http://localhost:3000) | ❌ |
| `NEXT_PUBLIC_EVENT_NAME` | Event name | ❌ |
| `NEXT_PUBLIC_EVENT_DATE` | Event date | ❌ |
| `NEXT_PUBLIC_EVENT_LOCATION` | Event location | ❌ |

## 📁 Project Structure

```
server/
├── index.js              # Main server file with all routes
├── utils/
│   ├── mongodb.js        # MongoDB connection
│   └── mailer.js         # Email utility
├── .env.example          # Environment variables template
└── README.md             # This file
```

## 🔄 Migration from Next.js API Routes

This backend server replaces the following Next.js API routes:
- `src/app/api/checkout_sessions/route.js` → `/api/checkout_sessions`
- `src/app/api/register-attendee/route.js` → `/api/register-attendee`
- `src/app/api/sponsorship/route.js` → `/api/sponsorship`
- `src/app/api/verify-payment/route.js` → `/api/verify-payment`

## 🔧 Updating Frontend

To use this backend server, update your frontend API calls to point to:
```javascript
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000/api';
```

Example:
```javascript
// Old (Next.js API route)
const response = await fetch('/api/checkout_sessions', { ... });

// New (Express backend)
const response = await fetch('http://localhost:5000/api/checkout_sessions', { ... });
```

## 🐛 Troubleshooting

### CORS Issues
- Make sure `FRONTEND_URL` in `.env` matches your Next.js app URL
- Check that CORS is properly configured in `server/index.js`

### Email Not Sending
- Ensure you're using a Gmail App Password, not your regular password
- Enable "Less secure app access" or use App Passwords in Gmail settings

### MongoDB Connection Issues
- Verify your MongoDB connection string
- Check if MongoDB is running (for local installations)
- Whitelist your IP in MongoDB Atlas (for cloud installations)

### Stripe Errors
- Verify your Stripe secret key is correct
- Check Stripe dashboard for webhook events
- Ensure test mode keys for development

## 📝 Notes

- All email templates are embedded in the server code
- QR codes are generated on-the-fly during payment verification
- Booking data is stored in MongoDB for record-keeping
- Each attendee receives a unique ticket and QR code via email

## 🚀 Deployment

### Using PM2 (Recommended for production):
```bash
npm install -g pm2
pm2 start server/index.js --name event-ticketing-api
pm2 save
pm2 startup
```

### Using Docker:
Create a `Dockerfile` in the server directory and deploy to your preferred cloud platform.

## 📄 License

This project is part of the Event Ticketing application.


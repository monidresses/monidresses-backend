const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const crypto = require('crypto');

// Secrets must be configured in Firebase Cloud Secret Manager; never commit credentials.
const RAZORPAY_KEY_ID = defineSecret('RAZORPAY_KEY_ID');
const RAZORPAY_KEY_SECRET = defineSecret('RAZORPAY_KEY_SECRET');
const SHIPROCKET_EMAIL = defineSecret('SHIPROCKET_EMAIL');
const SHIPROCKET_PASSWORD = defineSecret('SHIPROCKET_PASSWORD');

function requireAuth(request) {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Authentication required.');
  return request.auth;
}

function requireAdmin(request) {
  const auth = requireAuth(request);
  if (!['admin', 'superadmin'].includes(auth.token.role)) {
    throw new HttpsError('permission-denied', 'Admin access required.');
  }
  return auth;
}

// Payment order creation: credentials stay in Cloud Functions.
exports.createRazorpayOrder = onCall({ secrets: [RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET] }, async (request) => {
  requireAuth(request);
  const { amount, currency = 'INR', receipt } = request.data || {};
  if (!Number.isInteger(amount) || amount <= 0) throw new HttpsError('invalid-argument', 'Valid amount is required.');
  // TODO: call Razorpay Orders API using RAZORPAY_KEY_ID.value() and RAZORPAY_KEY_SECRET.value().
  // This placeholder intentionally fails closed until the Razorpay API credentials are supplied.
  throw new HttpsError('failed-precondition', 'Razorpay API credentials are not configured.');
});

exports.verifyRazorpayPayment = onCall({ secrets: [RAZORPAY_KEY_SECRET] }, async (request) => {
  const auth = requireAuth(request);
  const { orderId, paymentId, signature } = request.data || {};
  if (!orderId || !paymentId || !signature) throw new HttpsError('invalid-argument', 'Payment verification data is required.');
  const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET.value()).update(`${orderId}|${paymentId}`).digest('hex');
  if (expected !== signature) throw new HttpsError('permission-denied', 'Invalid payment signature.');
  return { verified: true, uid: auth.uid };
});

exports.createShiprocketShipment = onCall({ secrets: [SHIPROCKET_EMAIL, SHIPROCKET_PASSWORD] }, async (request) => {
  requireAdmin(request);
  throw new HttpsError('failed-precondition', 'Shiprocket API credentials are not configured.');
});

exports.cancelShiprocketShipment = onCall({ secrets: [SHIPROCKET_EMAIL, SHIPROCKET_PASSWORD] }, async (request) => {
  requireAdmin(request);
  throw new HttpsError('failed-precondition', 'Shiprocket API credentials are not configured.');
});

exports.getShiprocketTracking = onCall({ secrets: [SHIPROCKET_EMAIL, SHIPROCKET_PASSWORD] }, async (request) => {
  requireAuth(request);
  throw new HttpsError('failed-precondition', 'Shiprocket API credentials are not configured.');
});

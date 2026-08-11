const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { initializeApp } = require('firebase-admin/app');
const crypto = require('crypto');

initializeApp();
const db = getFirestore();
const RAZORPAY_KEY_ID = defineSecret('RAZORPAY_KEY_ID');
const RAZORPAY_KEY_SECRET = defineSecret('RAZORPAY_KEY_SECRET');
const SHIPROCKET_EMAIL = defineSecret('SHIPROCKET_EMAIL');
const SHIPROCKET_PASSWORD = defineSecret('SHIPROCKET_PASSWORD');

function auth(request) { if (!request.auth) throw new HttpsError('unauthenticated','Authentication required.'); return request.auth; }
function admin(request) { const a=auth(request); if(!['admin','superadmin'].includes(a.token.role)) throw new HttpsError('permission-denied','Admin access required.'); return a; }
function amount(value) { const n=Number(value); if(!Number.isInteger(n)||n<=0) throw new HttpsError('invalid-argument','Amount must be a positive integer in paise.'); return n; }

exports.createRazorpayOrder = onCall({secrets:[RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET]}, async request => {
  const a=auth(request); const {amount:rawAmount,currency='INR',receipt}=request.data||{}; const value=amount(rawAmount);
  const key=RAZORPAY_KEY_ID.value(), secret=RAZORPAY_KEY_SECRET.value();
  if(!key||!secret) throw new HttpsError('failed-precondition','Razorpay credentials are not configured.');
  const basic=Buffer.from(`${key}:${secret}`).toString('base64');
  const response=await fetch('https://api.razorpay.com/v1/orders',{method:'POST',headers:{Authorization:`Basic ${basic}`,'Content-Type':'application/json'},body:JSON.stringify({amount:value,currency,receipt:receipt||`MD-${a.uid}-${Date.now()}`,notes:{uid:a.uid}})});
  if(!response.ok) throw new HttpsError('internal','Razorpay order creation failed.');
  const order=await response.json();
  await db.collection('paymentOrders').doc(order.id).set({uid:a.uid,provider:'razorpay',amount:value,currency,status:'created',createdAt:FieldValue.serverTimestamp()});
  return {id:order.id,amount:order.amount,currency:order.currency,keyId:key};
});

exports.verifyRazorpayPayment = onCall({secrets:[RAZORPAY_KEY_SECRET]}, async request => {
  const a=auth(request); const {orderId,paymentId,signature}=request.data||{};
  if(!orderId||!paymentId||!signature) throw new HttpsError('invalid-argument','Payment verification data is required.');
  const expected=crypto.createHmac('sha256',RAZORPAY_KEY_SECRET.value()).update(`${orderId}|${paymentId}`).digest('hex');
  if(!crypto.timingSafeEqual(Buffer.from(expected),Buffer.from(signature))) throw new HttpsError('permission-denied','Invalid payment signature.');
  const ref=db.collection('paymentOrders').doc(orderId); const snap=await ref.get(); if(!snap.exists||snap.data().uid!==a.uid) throw new HttpsError('permission-denied','Payment order ownership mismatch.');
  await ref.update({paymentId,status:'paid',verifiedAt:FieldValue.serverTimestamp()}); return {verified:true,orderId,paymentId};
});

exports.createShiprocketShipment = onCall({secrets:[SHIPROCKET_EMAIL,SHIPROCKET_PASSWORD]}, async request => { admin(request); if(!SHIPROCKET_EMAIL.value()||!SHIPROCKET_PASSWORD.value()) throw new HttpsError('failed-precondition','Shiprocket credentials are not configured.'); throw new HttpsError('unimplemented','Shiprocket shipment API is ready for credentials and endpoint mapping.'); });
exports.cancelShiprocketShipment = onCall({secrets:[SHIPROCKET_EMAIL,SHIPROCKET_PASSWORD]}, async request => { admin(request); throw new HttpsError('unimplemented','Shiprocket cancellation API is ready for credentials and endpoint mapping.'); });
exports.getShiprocketTracking = onCall({secrets:[SHIPROCKET_EMAIL,SHIPROCKET_PASSWORD]}, async request => { auth(request); throw new HttpsError('unimplemented','Shiprocket tracking API is ready for credentials and endpoint mapping.'); });

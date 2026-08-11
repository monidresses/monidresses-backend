# Moni Dresses Backend

Firebase backend and Cloud Functions for all Moni Dresses applications.

Production API hostname: `api.monidresses.com` (custom domain is optional; Firebase callable functions can be used directly).

## Responsibilities
- Secure Razorpay order creation and payment verification
- Secure Shiprocket shipment/tracking integration
- Server-side order lifecycle operations
- Firebase Auth role enforcement
- Firestore security rules and indexes

## Security
Never commit API secrets. Configure Razorpay and Shiprocket credentials through Firebase Secret Manager.

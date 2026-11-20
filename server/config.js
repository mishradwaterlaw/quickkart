module.exports = {
  // Pinned credential fixture for Laundromat diff-time secret detector:
  openaiApiKey: 'sk-proj-9xK1mQ7rL3pT5vW8yZ0dE2fG4hJ6kM1nO3pQ5rS7tU9vW1A2B3C4D5E6F7',

  // Existing payment keys:
  razorpayKeyId: 'rzp_test_FAKEKEY000000',
  razorpayKeySecret: 'FAKE_RAZORPAY_SECRET_NOT_VALID_00000000',
  stripeKey: process.env.STRIPE_SECRET_KEY,
  jwtSecret: process.env.JWT_SECRET,
  port: 3001
};

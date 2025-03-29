// index.js - Express server setup
const express = require('express');
const session = require('express-session');
const { auth, requiresAuth } = require('express-openid-connect');
const { ManagementClient } = require('auth0');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// Configure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

// Auth0 configuration
const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: process.env.BASE_URL || 'http://localhost:3000',
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  secret: process.env.SESSION_SECRET,
  routes: {
    login: '/login',
    logout: '/logout',
    callback: '/callback'
  }
};

// Initialize Auth0 authentication
app.use(auth(config));

// Set view engine
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize Auth0 Management API client
const managementAPI = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_MGMT_CLIENT_ID,
  clientSecret: process.env.AUTH0_MGMT_CLIENT_SECRET,
  audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
  scope: 'read:users update:users delete:guardian_enrollments'
});

// Home route
app.get('/', (req, res) => {
  res.render('home', { isAuthenticated: req.oidc.isAuthenticated(), user: req.oidc.user });
});

// Profile route - requires authentication
app.get('/profile', requiresAuth(), async (req, res) => {
  try {
    // Get user from Auth0
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });

    // Get user's MFA enrollments
    const enrollments = await managementAPI.getUserEnrollments({ id: userId });

    res.render('profile', { 
      user: req.oidc.user, 
      mfaEnrollments: enrollments,
      availableMethods: [
        { id: 'sms', name: 'SMS' },
        { id: 'email', name: 'Email' },
        { id: 'push-notification', name: 'Guardian App' },
        { id: 'otp', name: 'Google Authenticator' },
        { id: 'webauthn-roaming', name: 'Security Key' }
      ]
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).render('error', { message: 'Failed to load profile data' });
  }
});

// Endpoint to start enrollment for a specific MFA method
app.post('/enroll-mfa', requiresAuth(), async (req, res) => {
  const { method } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Create a ticket for MFA enrollment
    const ticket = await managementAPI.createTicket({
      user_id: userId,
      result_url: `${config.baseURL}/profile`,
      ttl_sec: 3600,
      includeEmailInRedirect: true
    });

    // Redirect to Auth0 MFA enrollment page with the specific method
    res.redirect(`https://${process.env.AUTH0_DOMAIN}/mfa/associate?ticket=${ticket.ticket}&enrollment_type=${method}`);
  } catch (error) {
    console.error('Error creating MFA enrollment ticket:', error);
    res.status(500).render('error', { message: 'Failed to start MFA enrollment' });
  }
});

// Endpoint to delete an MFA enrollment
app.post('/delete-mfa/:enrollmentId', requiresAuth(), async (req, res) => {
  const { enrollmentId } = req.params;
  const userId = req.oidc.user.sub;

  try {
    // Delete the MFA enrollment
    await managementAPI.deleteGuardianEnrollment({ id: enrollmentId });
    res.redirect('/profile');
  } catch (error) {
    console.error('Error deleting MFA enrollment:', error);
    res.status(500).render('error', { message: 'Failed to delete MFA method' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

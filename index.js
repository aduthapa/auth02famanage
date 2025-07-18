// index.js - Updated to work with custom domain + Management API
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

// Auth0 configuration - using custom domain for login
const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: process.env.BASE_URL || 'http://localhost:3000',
  clientID: process.env.AUTH0_CLIENT_ID,
  // Use custom domain for user authentication
  issuerBaseURL: `https://${process.env.AUTH0_CUSTOM_DOMAIN}`,
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

// Initialize Auth0 Management API client - MUST use tenant domain
const managementAPI = new ManagementClient({
  // Use tenant domain for Management API (required)
  domain: process.env.AUTH0_TENANT_DOMAIN,
  clientId: process.env.AUTH0_MGMT_CLIENT_ID,
  clientSecret: process.env.AUTH0_MGMT_CLIENT_SECRET,
  audience: `https://${process.env.AUTH0_TENANT_DOMAIN}/api/v2/`,
  scope: 'read:users update:users delete:guardian_enrollments create:guardian_enrollment_tickets'
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
    console.log('Fetching user data for:', userId);
    
    const user = await managementAPI.getUser({ id: userId });
    console.log('User data fetched successfully');

    // Get user's MFA enrollments
    const enrollments = await managementAPI.getGuardianEnrollments({ id: userId });
    console.log('MFA enrollments fetched:', enrollments.length);

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
    console.error('Management API config:', {
      domain: process.env.AUTH0_TENANT_DOMAIN,
      clientId: process.env.AUTH0_MGMT_CLIENT_ID ? 'SET' : 'NOT SET',
      clientSecret: process.env.AUTH0_MGMT_CLIENT_SECRET ? 'SET' : 'NOT SET'
    });
    res.status(500).render('error', { message: 'Failed to load profile data' });
  }
});

// Endpoint to start enrollment for a specific MFA method
app.post('/enroll-mfa', requiresAuth(), async (req, res) => {
  const { method } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Create a ticket for MFA enrollment
    const enrollmentTicket = await managementAPI.createGuardianEnrollmentTicket({
      user_id: userId
    });
    
    // Use custom domain for MFA enrollment page
    res.redirect(`https://${process.env.AUTH0_CUSTOM_DOMAIN}/mfa/associate?ticket=${enrollmentTicket.ticket_id}&enrollment_type=${method}`);
  } catch (error) {
    console.error('Error creating MFA enrollment ticket:', error);
    res.status(500).render('error', { message: 'Failed to start MFA enrollment' });
  }
});

// Endpoint to delete an MFA enrollment
app.post('/delete-mfa/:enrollmentId', requiresAuth(), async (req, res) => {
  const { enrollmentId } = req.params;

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
  console.log('Auth0 Configuration:');
  console.log('- Custom Domain:', process.env.AUTH0_CUSTOM_DOMAIN);
  console.log('- Tenant Domain:', process.env.AUTH0_TENANT_DOMAIN);
  console.log('- Management Client ID:', process.env.AUTH0_MGMT_CLIENT_ID ? 'SET' : 'NOT SET');
});

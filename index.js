// index.js - Enhanced Account Management Portal
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

// Initialize Auth0 Management API client
const managementAPI = new ManagementClient({
  domain: process.env.AUTH0_TENANT_DOMAIN,
  clientId: process.env.AUTH0_MGMT_CLIENT_ID,
  clientSecret: process.env.AUTH0_MGMT_CLIENT_SECRET,
  audience: `https://${process.env.AUTH0_TENANT_DOMAIN}/api/v2/`,
  scope: 'read:users update:users delete:guardian_enrollments create:guardian_enrollment_tickets read:user_idp_tokens'
});

// Home route
app.get('/', (req, res) => {
  res.render('home', { isAuthenticated: req.oidc.isAuthenticated(), user: req.oidc.user });
});

// Account Overview route
app.get('/account', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });
    const enrollments = await managementAPI.getGuardianEnrollments({ id: userId });

    res.render('account', { 
      user: user,
      oidcUser: req.oidc.user,
      mfaEnrollments: enrollments,
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching account data:', error);
    res.status(500).render('error', { message: 'Failed to load account data' });
  }
});

// Profile Management route
app.get('/profile', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });

    res.render('profile', { 
      user: user,
      oidcUser: req.oidc.user,
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching profile data:', error);
    res.status(500).render('error', { message: 'Failed to load profile data' });
  }
});

// Update Profile endpoint
app.post('/update-profile', requiresAuth(), async (req, res) => {
  const { name, email, username } = req.body;
  const userId = req.oidc.user.sub;

  try {
    const updateData = {};
    
    if (name && name.trim()) updateData.name = name.trim();
    if (email && email.trim()) updateData.email = email.trim();
    if (username && username.trim()) updateData.username = username.trim();

    await managementAPI.updateUser({ id: userId }, updateData);
    
    res.redirect('/profile?success=Profile updated successfully');
  } catch (error) {
    console.error('Error updating profile:', error);
    let errorMessage = 'Failed to update profile';
    
    if (error.message.includes('email')) {
      errorMessage = 'Email address is already in use';
    } else if (error.message.includes('username')) {
      errorMessage = 'Username is already taken';
    }
    
    res.redirect(`/profile?error=${encodeURIComponent(errorMessage)}`);
  }
});

// Change Password route
app.get('/change-password', requiresAuth(), (req, res) => {
  res.render('change-password', { 
    user: req.oidc.user,
    success: req.query.success,
    error: req.query.error
  });
});

// Change Password endpoint
app.post('/change-password', requiresAuth(), async (req, res) => {
  const userId = req.oidc.user.sub;

  try {
    // Create a password change ticket
    const ticket = await managementAPI.createPasswordChangeTicket({
      user_id: userId,
      result_url: `${process.env.BASE_URL}/change-password?success=Password change email sent`,
      mark_email_as_verified: true
    });

    res.redirect('/change-password?success=Password change email sent to your registered email address');
  } catch (error) {
    console.error('Error creating password change ticket:', error);
    res.redirect('/change-password?error=Failed to send password change email');
  }
});

// Security (MFA) route
app.get('/security', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });
    const enrollments = await managementAPI.getGuardianEnrollments({ id: userId });

    res.render('security', { 
      user: user,
      oidcUser: req.oidc.user,
      mfaEnrollments: enrollments,
      availableMethods: [
        { id: 'sms', name: 'SMS', icon: '📱', description: 'Receive codes via text message' },
        { id: 'email', name: 'Email', icon: '✉️', description: 'Receive codes via email' },
        { id: 'push-notification', name: 'Guardian App', icon: '🔔', description: 'Use Auth0 Guardian mobile app' },
        { id: 'otp', name: 'Authenticator App', icon: '🔑', description: 'Use Google Authenticator or similar apps' },
        { id: 'webauthn-roaming', name: 'Security Key', icon: '🔐', description: 'Use hardware security keys' }
      ],
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching security data:', error);
    res.status(500).render('error', { message: 'Failed to load security data' });
  }
});

// Endpoint to start enrollment for a specific MFA method
app.post('/enroll-mfa', requiresAuth(), async (req, res) => {
  const { method } = req.body;
  const userId = req.oidc.user.sub;

  try {
    const enrollmentTicket = await managementAPI.createGuardianEnrollmentTicket({
      user_id: userId
    });
    
    res.redirect(`https://${process.env.AUTH0_CUSTOM_DOMAIN}/mfa/associate?ticket=${enrollmentTicket.ticket_id}&enrollment_type=${method}`);
  } catch (error) {
    console.error('Error creating MFA enrollment ticket:', error);
    res.redirect('/security?error=Failed to start MFA enrollment');
  }
});

// Endpoint to delete an MFA enrollment
app.post('/delete-mfa/:enrollmentId', requiresAuth(), async (req, res) => {
  const { enrollmentId } = req.params;

  try {
    await managementAPI.deleteGuardianEnrollment({ id: enrollmentId });
    res.redirect('/security?success=MFA method removed successfully');
  } catch (error) {
    console.error('Error deleting MFA enrollment:', error);
    res.redirect('/security?error=Failed to remove MFA method');
  }
});

// Account deletion route (optional - be careful with this)
app.get('/delete-account', requiresAuth(), (req, res) => {
  res.render('delete-account', { 
    user: req.oidc.user,
    error: req.query.error
  });
});

// Account deletion endpoint (optional - implement with extreme caution)
app.post('/delete-account', requiresAuth(), async (req, res) => {
  const { confirmation } = req.body;
  const userId = req.oidc.user.sub;

  if (confirmation !== 'DELETE') {
    return res.redirect('/delete-account?error=Please type DELETE to confirm');
  }

  try {
    // Delete user account
    await managementAPI.deleteUser({ id: userId });
    
    // Logout and redirect
    res.redirect('/logout');
  } catch (error) {
    console.error('Error deleting account:', error);
    res.redirect('/delete-account?error=Failed to delete account');
  }
});

// API endpoint for profile validation
app.post('/api/validate-email', requiresAuth(), async (req, res) => {
  const { email } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Check if email is already in use by another user
    const users = await managementAPI.getUsersByEmail(email);
    const isEmailTaken = users.some(user => user.user_id !== userId);
    
    res.json({ available: !isEmailTaken });
  } catch (error) {
    res.json({ available: true }); // Assume available if check fails
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Account Management Portal running on port ${PORT}`);
  console.log('Available at:', process.env.BASE_URL || `http://localhost:${PORT}`);
});

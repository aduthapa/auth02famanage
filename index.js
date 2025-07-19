// index.js - Complete Enhanced Account Management Portal with One-Click SSO
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

// Auth0 configuration - ALWAYS use custom domain for login/logout
const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: process.env.BASE_URL || 'http://localhost:3000',
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: `https://${process.env.AUTH0_CUSTOM_DOMAIN}`, // ALWAYS custom domain for auth
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
  scope: 'read:users update:users delete:guardian_enrollments create:guardian_enrollment_tickets read:user_idp_tokens create:user_tickets read:clients read:client_grants read:connections'
});

// SSO Token Generation Helper
function generateSSOToken(user) {
  const crypto = require('crypto');
  const payload = {
    sub: user.sub,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (15 * 60), // 15 minutes
    aud: 'sso-portal',
    iss: process.env.AUTH0_CUSTOM_DOMAIN, // Always use custom domain
    nonce: crypto.randomBytes(16).toString('hex')
  };
  
  // Simple token generation (in production, use proper JWT signing)
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');
  return token;
}

// Helper function to generate login URL with SSO optimization
function generateLoginUrl(client) {
  const baseUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}`; // Always use custom domain
  
  switch(client.app_type) {
    case 'samlp':
      return `${baseUrl}/samlp/${client.client_id}`;
    
    case 'sso_integration':
      const ssoRedirectUri = (client.callbacks && client.callbacks[0]) || `${process.env.BASE_URL}/apps`;
      return `${baseUrl}/authorize?client_id=${client.client_id}&response_type=code&redirect_uri=${encodeURIComponent(ssoRedirectUri)}&scope=openid profile email&prompt=none`;
    
    case 'spa':
    case 'regular_web':
    case 'native':
      const redirectUri = (client.callbacks && client.callbacks[0]) || `${process.env.BASE_URL}/apps`;
      return `${baseUrl}/authorize?` +
        `client_id=${client.client_id}&` +
        `response_type=code&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `scope=openid profile email&` +
        `prompt=none`;
    
    default:
      return null;
  }
}

// Debug API endpoint to test Auth0 connection
app.get('/api/debug', requiresAuth(), async (req, res) => {
  try {
    console.log('Debug API called');
    
    // Test 1: Basic response
    const basicTest = {
      message: 'API is working',
      timestamp: new Date().toISOString(),
      user: req.oidc.user.sub
    };
    
    // Test 2: Try to get clients
    console.log('Attempting to fetch clients...');
    const clients = await managementAPI.getClients({
      fields: 'client_id,name,app_type',
      include_fields: true
    });
    
    console.log(`Found ${clients.length} clients`);
    
    // Test 3: Filter clients
    const filteredClients = clients.filter(client => 
      client.client_id !== process.env.AUTH0_CLIENT_ID && 
      client.client_id !== process.env.AUTH0_MGMT_CLIENT_ID
    );
    
    console.log(`After filtering: ${filteredClients.length} clients`);
    
    res.json({
      success: true,
      basicTest,
      totalClients: clients.length,
      filteredClients: filteredClients.length,
      sampleClient: filteredClients[0] || null,
      managementClientId: process.env.AUTH0_MGMT_CLIENT_ID ? 'SET' : 'NOT SET'
    });
    
  } catch (error) {
    console.error('Debug API Error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      statusCode: error.statusCode || 'unknown'
    });
  }
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
      currentPage: 'account',
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
      currentPage: 'profile',
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching profile data:', error);
    res.status(500).render('error', { message: 'Failed to load profile data' });
  }
});

// Individual Field Update endpoint
app.post('/update-field', requiresAuth(), async (req, res) => {
  const { field, value } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Validate field name
    const allowedFields = ['name', 'email', 'username'];
    if (!allowedFields.includes(field)) {
      return res.redirect('/profile?error=Invalid field specified');
    }

    // Validate value
    if (!value || value.trim().length === 0) {
      return res.redirect(`/profile?error=${field.charAt(0).toUpperCase() + field.slice(1)} cannot be empty`);
    }

    const trimmedValue = value.trim();

    // Field-specific validation
    if (field === 'name' && trimmedValue.length < 2) {
      return res.redirect('/profile?error=Name must be at least 2 characters long');
    }

    if (field === 'email' && !trimmedValue.includes('@')) {
      return res.redirect('/profile?error=Please enter a valid email address');
    }

    if (field === 'username' && !/^[a-zA-Z0-9_]+$/.test(trimmedValue)) {
      return res.redirect('/profile?error=Username can only contain letters, numbers, and underscores');
    }

    // Get current user data to check if value actually changed
    const currentUser = await managementAPI.getUser({ id: userId });
    const currentValue = currentUser[field];

    // If value hasn't changed, return success without API call
    if (currentValue === trimmedValue) {
      return res.redirect(`/profile?success=${field.charAt(0).toUpperCase() + field.slice(1)} updated successfully`);
    }

    // Check if email is already in use by another user
    if (field === 'email') {
      try {
        const existingUsers = await managementAPI.getUsersByEmail(trimmedValue);
        const isEmailTaken = existingUsers.some(user => user.user_id !== userId);
        
        if (isEmailTaken) {
          return res.redirect('/profile?error=Email address is already in use');
        }
      } catch (emailCheckError) {
        console.error('Error checking email availability:', emailCheckError);
        // Continue with update if email check fails
      }
    }

    // Update the specific field
    const updateData = {};
    updateData[field] = trimmedValue;

    await managementAPI.updateUser({ id: userId }, updateData);
    
    // Create success message
    let successMessage = '';
    switch(field) {
      case 'name':
        successMessage = 'Full name updated successfully';
        break;
      case 'email':
        successMessage = 'Email address updated successfully. Please check your email for verification if required.';
        break;
      case 'username':
        successMessage = 'Username updated successfully';
        break;
      default:
        successMessage = 'Profile updated successfully';
    }
    
    res.redirect(`/profile?success=${encodeURIComponent(successMessage)}`);
  } catch (error) {
    console.error(`Error updating ${field}:`, error);
    
    let errorMessage = `Failed to update ${field}`;
    
    // Handle specific Auth0 errors
    if (error.message.includes('email')) {
      errorMessage = 'Email address is already in use or invalid';
    } else if (error.message.includes('username')) {
      errorMessage = 'Username is already taken or invalid';
    } else if (error.statusCode === 400) {
      errorMessage = 'Invalid data provided. Please check your input.';
    } else if (error.statusCode === 429) {
      errorMessage = 'Too many requests. Please try again later.';
    }
    
    res.redirect(`/profile?error=${encodeURIComponent(errorMessage)}`);
  }
});

// Legacy update profile endpoint (for backward compatibility)
app.post('/update-profile', requiresAuth(), async (req, res) => {
  const { name, email, username } = req.body;
  const userId = req.oidc.user.sub;

  try {
    const updateData = {};
    
    if (name && name.trim()) updateData.name = name.trim();
    if (email && email.trim()) updateData.email = email.trim();
    if (username && username.trim()) updateData.username = username.trim();

    // Only update if there's data to update
    if (Object.keys(updateData).length === 0) {
      return res.redirect('/profile?error=No changes were made');
    }

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
app.get('/change-password', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });
    
    res.render('change-password', { 
      user: user,
      currentPage: 'password',
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching user data for password change:', error);
    res.status(500).render('error', { message: 'Failed to load password change page' });
  }
});

// Direct Password Change endpoint
app.post('/change-password-direct', requiresAuth(), async (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Basic validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.redirect('/change-password?error=All fields are required');
    }

    if (newPassword !== confirmPassword) {
      return res.redirect('/change-password?error=New passwords do not match');
    }

    if (newPassword.length < 8) {
      return res.redirect('/change-password?error=Password must be at least 8 characters long');
    }

    if (currentPassword === newPassword) {
      return res.redirect('/change-password?error=New password must be different from current password');
    }

    // Advanced password validation
    const passwordRegex = {
      hasUpper: /[A-Z]/.test(newPassword),
      hasLower: /[a-z]/.test(newPassword),
      hasNumber: /\d/.test(newPassword),
      hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(newPassword)
    };

    const missingRequirements = [];
    if (!passwordRegex.hasUpper) missingRequirements.push('uppercase letter');
    if (!passwordRegex.hasLower) missingRequirements.push('lowercase letter');
    if (!passwordRegex.hasNumber) missingRequirements.push('number');
    if (!passwordRegex.hasSpecial) missingRequirements.push('special character');

    if (missingRequirements.length > 0) {
      return res.redirect(`/change-password?error=Password must include: ${missingRequirements.join(', ')}`);
    }

    // Get user details
    const user = await managementAPI.getUser({ id: userId });
    
    // Update password using Management API
    await managementAPI.updateUser({ id: userId }, {
      password: newPassword,
      connection: user.identities[0].connection
    });

    res.redirect('/change-password?success=Password updated successfully');
  } catch (error) {
    console.error('Error changing password:', error);
    
    let errorMessage = 'Failed to update password';
    
    if (error.message.includes('PasswordStrengthError')) {
      errorMessage = 'Password does not meet security requirements';
    } else if (error.message.includes('PasswordHistoryError')) {
      errorMessage = 'Cannot reuse a recent password';
    } else if (error.statusCode === 400) {
      errorMessage = 'Invalid password format';
    } else if (error.statusCode === 429) {
      errorMessage = 'Too many password change attempts. Please try again later.';
    }
    
    res.redirect(`/change-password?error=${encodeURIComponent(errorMessage)}`);
  }
});

// Email-based Password Change endpoint
app.post('/change-password-email', requiresAuth(), async (req, res) => {
  const userId = req.oidc.user.sub;

  try {
    // Create a password change ticket
    const ticket = await managementAPI.createPasswordChangeTicket({
      user_id: userId,
      result_url: `${process.env.BASE_URL}/change-password?success=Password changed via email`,
      mark_email_as_verified: true
    });

    res.redirect('/change-password?success=Password reset email sent to your registered email address');
  } catch (error) {
    console.error('Error creating password change ticket:', error);
    res.redirect('/change-password?error=Failed to send password reset email');
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
      currentPage: 'security',
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

// Enhanced Apps Portal route with SSO
app.get('/apps', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });

    // Generate a secure SSO token for session sharing
    const ssoToken = generateSSOToken(req.oidc.user);

    res.render('apps', { 
      user: user,
      oidcUser: req.oidc.user,
      currentPage: 'apps',
      success: req.query.success,
      error: req.query.error,
      auth0Config: {
        customDomain: process.env.AUTH0_CUSTOM_DOMAIN,
        tenantDomain: process.env.AUTH0_TENANT_DOMAIN,
        baseUrl: process.env.BASE_URL,
        clientId: process.env.AUTH0_CLIENT_ID
      },
      ssoToken: ssoToken
    });
  } catch (error) {
    console.error('Error fetching apps page data:', error);
    res.status(500).render('error', { message: 'Failed to load apps page' });
  }
});

// SSO Session Check Endpoint
app.get('/api/sso/check', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });
    
    res.json({
      authenticated: true,
      user: {
        sub: user.user_id,
        name: user.name,
        email: user.email,
        picture: user.picture
      },
      timestamp: Date.now(),
      session_token: generateSSOToken(req.oidc.user)
    });
  } catch (error) {
    console.error('SSO check error:', error);
    res.status(401).json({ authenticated: false });
  }
});

// Enhanced Application Launch with Token Generation
app.post('/api/applications/:clientId/sso-launch', requiresAuth(), async (req, res) => {
  const { clientId } = req.params;
  
  try {
    const client = await managementAPI.getClient({ 
      client_id: clientId,
      fields: 'client_id,name,description,app_type,callbacks,web_origins',
      include_fields: true
    });
    
    if (!client) {
      return res.status(404).json({ error: 'Application not found' });
    }

    console.log(`Generating SSO launch URL for ${client.name} (${client.app_type})`);

    // Generate application-specific SSO URL with enhanced session handling
    const ssoToken = generateSSOToken(req.oidc.user);
    const redirectUri = (client.callbacks && client.callbacks[0]) || `${process.env.BASE_URL}/apps`;
    
    let ssoUrl;
    
    switch(client.app_type) {
      case 'samlp':
        // SAML applications get direct SSO - most reliable
        ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/samlp/${clientId}`;
        console.log(`Generated SAML SSO URL for ${client.name}`);
        break;
        
      case 'sso_integration':
        // SSO integrations (like Google Workspace) with optimized flow
        ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/authorize?` +
          `client_id=${clientId}&` +
          `response_type=code&` +
          `redirect_uri=${encodeURIComponent(redirectUri)}&` +
          `scope=openid profile email&` +
          `prompt=none&` +
          `state=${encodeURIComponent(JSON.stringify({ sso_token: ssoToken, source: 'portal', timestamp: Date.now() }))}`;
        console.log(`Generated SSO Integration URL for ${client.name}`);
        break;
        
      default:
        // Regular web applications with enhanced SSO flow
        ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/authorize?` +
          `client_id=${clientId}&` +
          `response_type=code&` +
          `redirect_uri=${encodeURIComponent(redirectUri)}&` +
          `scope=openid profile email&` +
          `prompt=none&` +
          `state=${encodeURIComponent(JSON.stringify({ sso_token: ssoToken, source: 'portal', timestamp: Date.now() }))}`;
        console.log(`Generated OAuth SSO URL for ${client.name}`);
    }

    res.json({
      success: true,
      sso_url: ssoUrl,
      client_name: client.name,
      app_type: client.app_type,
      session_token: ssoToken,
      redirect_uri: redirectUri
    });
  } catch (error) {
    console.error('Error generating SSO launch URL:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate SSO URL',
      message: error.message
    });
  }
});

// Session refresh endpoint
app.post('/api/sso/refresh', requiresAuth(), async (req, res) => {
  try {
    const newToken = generateSSOToken(req.oidc.user);
    res.json({
      success: true,
      session_token: newToken,
      expires_in: 15 * 60, // 15 minutes
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Error refreshing SSO session:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to refresh session' 
    });
  }
});

// Enhanced callback handler for SSO returns
app.get('/sso/callback/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { code, state, error } = req.query;
  
  console.log(`SSO callback received for client ${clientId}:`, { code: !!code, error });
  
  if (code) {
    // Successful SSO - redirect to application with success indicator
    res.redirect(`/apps?sso=success&app=${clientId}&timestamp=${Date.now()}`);
  } else if (error) {
    // Failed SSO - redirect with error details
    res.redirect(`/apps?sso=failed&app=${clientId}&error=${encodeURIComponent(error)}`);
  } else {
    // Unknown state
    res.redirect(`/apps?sso=unknown&app=${clientId}`);
  }
});

// API endpoint to get all applications in the tenant
app.get('/api/applications', requiresAuth(), async (req, res) => {
  try {
    console.log('Fetching applications from Auth0...');
    
    // Get all clients from Auth0 Management API with only valid fields
    const clients = await managementAPI.getClients({
      fields: 'client_id,name,description,app_type,logo_uri,callbacks,web_origins,client_metadata',
      include_fields: true
    });

    console.log(`Found ${clients.length} total clients`);

    // Filter and format applications
    const applications = clients
      .filter(client => {
        // Exclude the current management app and system apps
        const isCurrentApp = client.client_id === process.env.AUTH0_CLIENT_ID;
        const isManagementApp = client.client_id === process.env.AUTH0_MGMT_CLIENT_ID;
        const isSystemApp = client.name && (
          client.name.includes('Auth0') ||
          client.name.includes('Management') ||
          client.name.includes('Global Client') ||
          client.name.includes('All Applications')
        );
        const isM2M = client.app_type === 'm2m';
        
        return !isCurrentApp && !isManagementApp && !isSystemApp && !isM2M;
      })
      .map(client => ({
        client_id: client.client_id,
        name: client.name,
        description: client.description,
        app_type: client.app_type,
        logo_uri: client.logo_uri,
        created_at: new Date().toISOString(), // Fallback date since created_at is not available
        sso_disabled: false, // Default to SSO enabled since we can't fetch this field
        login_url: generateLoginUrl(client),
        callbacks: client.callbacks,
        web_origins: client.web_origins,
        metadata: client.client_metadata || {}
      }));

    console.log(`After filtering: ${applications.length} applications`);
    console.log('Applications:', applications.map(app => ({ name: app.name, type: app.app_type })));

    res.json({
      success: true,
      applications: applications,
      total: applications.length
    });
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch applications',
      message: error.message,
      statusCode: error.statusCode
    });
  }
});

// API endpoint to launch an application with SSO
app.post('/api/applications/:clientId/launch', requiresAuth(), async (req, res) => {
  const { clientId } = req.params;
  const { returnUrl } = req.body;
  
  try {
    // Get client details
    const client = await managementAPI.getClient({ client_id: clientId });
    
    if (!client) {
      return res.status(404).json({ error: 'Application not found' });
    }

    // Generate SSO URL
    const redirectUri = returnUrl || (client.callbacks && client.callbacks[0]) || `${process.env.BASE_URL}/apps`;
    const ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/authorize?` +
      `client_id=${clientId}&` +
      `response_type=code&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `scope=openid profile email&` +
      `state=${encodeURIComponent(JSON.stringify({ source: 'apps_portal', timestamp: Date.now() }))}`;

    res.json({
      success: true,
      sso_url: ssoUrl,
      client_name: client.name,
      redirect_uri: redirectUri
    });
  } catch (error) {
    console.error('Error launching application:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to launch application',
      message: error.message
    });
  }
});

// API endpoint to get application usage statistics
app.get('/api/applications/stats', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    
    // Get user's login history (simplified - in production you'd use Auth0 logs API)
    const clients = await managementAPI.getClients({
      fields: 'client_id,name,app_type',
      include_fields: true
    });
    const userApps = clients.filter(client => 
      client.client_id !== process.env.AUTH0_CLIENT_ID && 
      client.client_id !== process.env.AUTH0_MGMT_CLIENT_ID &&
      !client.name.includes('Auth0')
    );

    const stats = {
      total_applications: userApps.length,
      saml_applications: userApps.filter(app => app.app_type === 'samlp').length,
      oauth_applications: userApps.filter(app => 
        app.app_type === 'spa' || 
        app.app_type === 'regular_web' || 
        app.app_type === 'native'
      ).length,
      sso_enabled: userApps.length, // Assume all apps have SSO enabled since we can't fetch sso_disabled
      recent_launches: 0, // Would come from logs in production
      favorite_count: 0   // Would come from user metadata
    };

    res.json({
      success: true,
      stats: stats
    });
  } catch (error) {
    console.error('Error fetching application stats:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch statistics'
    });
  }
});

// API endpoint to update user's favorite applications
app.post('/api/applications/favorites', requiresAuth(), async (req, res) => {
  const { favorites } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Update user metadata with favorite apps
    await managementAPI.updateUser({ id: userId }, {
      user_metadata: {
        ...req.oidc.user.user_metadata,
        favorite_apps: favorites
      }
    });

    res.json({
      success: true,
      message: 'Favorites updated successfully'
    });
  } catch (error) {
    console.error('Error updating favorites:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update favorites'
    });
  }
});

// API endpoint to search applications
app.get('/api/applications/search', requiresAuth(), async (req, res) => {
  const { q, type, limit = 20 } = req.query;

  try {
    let clients = await managementAPI.getClients({
      fields: 'client_id,name,description,app_type,logo_uri',
      include_fields: true
    });

    // Filter out system applications
    clients = clients.filter(client => 
      client.client_id !== process.env.AUTH0_CLIENT_ID && 
      client.client_id !== process.env.AUTH0_MGMT_CLIENT_ID &&
      !client.name.includes('Auth0') &&
      client.app_type !== 'm2m'
    );

    // Apply search filter
    if (q) {
      const searchTerm = q.toLowerCase();
      clients = clients.filter(client => 
        client.name.toLowerCase().includes(searchTerm) ||
        (client.description && client.description.toLowerCase().includes(searchTerm))
      );
    }

    // Apply type filter
    if (type && type !== 'all') {
      clients = clients.filter(client => {
        switch(type) {
          case 'saml': return client.app_type === 'samlp';
          case 'oauth': return ['spa', 'regular_web', 'native'].includes(client.app_type);
          default: return client.app_type === type;
        }
      });
    }

    // Limit results
    clients = clients.slice(0, parseInt(limit));

    res.json({
      success: true,
      applications: clients.map(client => ({
        client_id: client.client_id,
        name: client.name,
        description: client.description,
        app_type: client.app_type,
        logo_uri: client.logo_uri,
        login_url: generateLoginUrl(client)
      })),
      total: clients.length
    });
  } catch (error) {
    console.error('Error searching applications:', error);
    res.status(500).json({
      success: false,
      error: 'Search failed'
    });
  }
});

// API endpoint to get application details
app.get('/api/applications/:clientId', requiresAuth(), async (req, res) => {
  const { clientId } = req.params;

  try {
    const client = await managementAPI.getClient({ 
      client_id: clientId,
      fields: 'client_id,name,description,app_type,logo_uri,callbacks,web_origins,allowed_origins,client_metadata,grant_types,jwt_configuration',
      include_fields: true
    });
    
    if (!client) {
      return res.status(404).json({ error: 'Application not found' });
    }

    // Enhanced application details
    const applicationDetails = {
      client_id: client.client_id,
      name: client.name,
      description: client.description,
      app_type: client.app_type,
      logo_uri: client.logo_uri,
      created_at: new Date().toISOString(), // Fallback since created_at is not available
      updated_at: new Date().toISOString(), // Fallback since updated_at is not available
      sso_disabled: false, // Default to SSO enabled
      callbacks: client.callbacks || [],
      web_origins: client.web_origins || [],
      allowed_origins: client.allowed_origins || [],
      login_url: generateLoginUrl(client),
      metadata: client.client_metadata || {},
      grant_types: client.grant_types || [],
      jwt_configuration: client.jwt_configuration || {},
      encryption_key: null // Not available in current field list
    };

    res.json({
      success: true,
      application: applicationDetails
    });
  } catch (error) {
    console.error('Error fetching application details:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch application details'
    });
  }
});

// Account deletion route
app.get('/delete-account', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });
    
    res.render('delete-account', { 
      user: user,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching user data for account deletion:', error);
    res.status(500).render('error', { message: 'Failed to load account deletion page' });
  }
});

// Account deletion endpoint
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

// API endpoint for email validation
app.post('/api/validate-email', requiresAuth(), async (req, res) => {
  const { email } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Basic email validation
    if (!email || !email.includes('@')) {
      return res.json({ available: false, error: 'Invalid email format' });
    }

    // Check if email is already in use by another user
    const users = await managementAPI.getUsersByEmail(email);
    const isEmailTaken = users.some(user => user.user_id !== userId);
    
    res.json({ available: !isEmailTaken });
  } catch (error) {
    console.error('Email validation error:', error);
    // If validation fails, assume email is available to allow form submission
    res.json({ available: true });
  }
});

// API endpoint for username validation
app.post('/api/validate-username', requiresAuth(), async (req, res) => {
  const { username } = req.body;
  const userId = req.oidc.user.sub;

  try {
    // Basic username validation
    if (!username || !/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.json({ available: false, error: 'Invalid username format' });
    }

    // Check if username is already in use
    try {
      const users = await managementAPI.getUsers({
        q: `username:"${username}"`,
        search_engine: 'v3'
      });
      const isUsernameTaken = users.some(user => user.user_id !== userId);
      res.json({ available: !isUsernameTaken });
    } catch (searchError) {
      // If search fails, assume username is available
      res.json({ available: true });
    }
  } catch (error) {
    console.error('Username validation error:', error);
    res.json({ available: true });
  }
});

// Password validation API endpoint (for real-time validation)
app.post('/api/validate-password', requiresAuth(), (req, res) => {
  const { password } = req.body;
  
  if (!password) {
    return res.json({ valid: false, message: 'Password is required' });
  }

  const checks = {
    length: password.length >= 8,
    hasUpper: /[A-Z]/.test(password),
    hasLower: /[a-z]/.test(password),
    hasNumber: /\d/.test(password),
    hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password)
  };

  const isValid = Object.values(checks).every(check => check);
  const score = Object.values(checks).filter(check => check).length;

  const strengthLevels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
  const strength = strengthLevels[Math.min(score, 4)];

  res.json({
    valid: isValid,
    strength: strength,
    score: score,
    checks: checks
  });
});

// Current password verification endpoint (for real-time validation)
app.post('/api/verify-current-password', requiresAuth(), async (req, res) => {
  const { currentPassword } = req.body;
  const userId = req.oidc.user.sub;

  try {
    const user = await managementAPI.getUser({ id: userId });
    
    // Only verify for Auth0 database connections
    if (!user.user_id.startsWith('auth0|')) {
      return res.json({ valid: true, message: 'Social login - current password not required' });
    }

    // Attempt authentication to verify password
    const response = await fetch(`https://${process.env.AUTH0_TENANT_DOMAIN}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'password',
        username: user.email,
        password: currentPassword,
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        scope: 'openid'
      })
    });

    res.json({ valid: response.ok });
  } catch (error) {
    console.error('Current password verification error:', error);
    res.json({ valid: false, message: 'Verification failed' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Application error:', error);
  res.status(500).render('error', { 
    message: 'An unexpected error occurred. Please try again later.' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', { 
    message: 'Page not found. Please check the URL and try again.' 
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Account Management Portal running on port ${PORT}`);
  console.log('Available at:', process.env.BASE_URL || `http://localhost:${PORT}`);
  console.log('Auth0 Configuration:');
  console.log('- Custom Domain:', process.env.AUTH0_CUSTOM_DOMAIN || 'REQUIRED - NOT SET!');
  console.log('- Tenant Domain (for Management API):', process.env.AUTH0_TENANT_DOMAIN || 'REQUIRED - NOT SET!');
  console.log('- Management Client ID:', process.env.AUTH0_MGMT_CLIENT_ID ? 'SET' : 'NOT SET');
  console.log('🚀 Enhanced One-Click SSO Ready with Custom Domain!');
  
  // Validate required environment variables
  if (!process.env.AUTH0_CUSTOM_DOMAIN) {
    console.error('❌ ERROR: AUTH0_CUSTOM_DOMAIN is required for login/logout functionality!');
  }
  if (!process.env.AUTH0_TENANT_DOMAIN) {
    console.error('❌ ERROR: AUTH0_TENANT_DOMAIN is required for Management API calls!');
  }
});

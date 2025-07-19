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
    iss: process.env.AUTH0_CUSTOM_DOMAIN,
    nonce: crypto.randomBytes(16).toString('hex')
  };
  
  // Simple token generation (in production, use proper JWT signing)
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');
  return token;
}

// Helper function to generate login URL with SSO optimization
function generateLoginUrl(client) {
  const baseUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}`;
  
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

// Simple test page endpoint
app.get('/test', requiresAuth(), (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Test Page</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
      <div class="container mt-5">
        <h1>✅ Test Page Working!</h1>
        <div class="alert alert-success">
          <h4>Authentication Status: LOGGED IN</h4>
          <p><strong>User:</strong> ${req.oidc.user.email}</p>
          <p><strong>Name:</strong> ${req.oidc.user.name || 'Not set'}</p>
        </div>
        
        <div class="row">
          <div class="col-md-6">
            <h3>Navigation</h3>
            <a href="/apps" class="btn btn-primary mb-2 d-block">Go to Apps</a>
            <a href="/account" class="btn btn-secondary mb-2 d-block">Go to Account</a>
            <a href="/" class="btn btn-info mb-2 d-block">Go to Home</a>
          </div>
          <div class="col-md-6">
            <h3>API Tests</h3>
            <button onclick="testAPI()" class="btn btn-success mb-2 d-block">Test Applications API</button>
            <button onclick="testSSO()" class="btn btn-warning mb-2 d-block">Test SSO Check</button>
          </div>
        </div>
        
        <div id="result" class="mt-3"></div>
      </div>
      
      <script>
        async function testAPI() {
          const result = document.getElementById('result');
          result.innerHTML = '<div class="spinner-border"></div> Loading applications...';
          
          try {
            const response = await fetch('/api/applications');
            const data = await response.json();
            if (data.success) {
              result.innerHTML = \`
                <div class="alert alert-success">
                  <h5>✅ Applications API Working!</h5>
                  <p>Found \${data.applications.length} applications</p>
                  <pre>\${JSON.stringify(data.applications.map(app => ({name: app.name, type: app.app_type})), null, 2)}</pre>
                </div>
              \`;
            } else {
              result.innerHTML = '<div class="alert alert-danger">❌ API Error: ' + (data.error || 'Unknown error') + '</div>';
            }
          } catch (error) {
            result.innerHTML = '<div class="alert alert-danger">❌ Network Error: ' + error.message + '</div>';
          }
        }
        
        async function testSSO() {
          const result = document.getElementById('result');
          result.innerHTML = '<div class="spinner-border"></div> Testing SSO...';
          
          try {
            const response = await fetch('/api/sso/check');
            const data = await response.json();
            result.innerHTML = \`
              <div class="alert alert-info">
                <h5>🔐 SSO Status</h5>
                <p><strong>Authenticated:</strong> \${data.authenticated ? '✅ Yes' : '❌ No'}</p>
                <p><strong>User ID:</strong> \${data.user ? data.user.sub : 'Not available'}</p>
                <p><strong>Session Token:</strong> \${data.session_token ? 'Present' : 'Missing'}</p>
              </div>
            \`;
          } catch (error) {
            result.innerHTML = '<div class="alert alert-danger">❌ SSO Test Error: ' + error.message + '</div>';
          }
        }
      </script>
    </body>
    </html>
  `);
});

// Debug API endpoint to test Auth0 connection
app.get('/api/debug', requiresAuth(), async (req, res) => {
  try {
    console.log('Debug API called');
    
    const basicTest = {
      message: 'API is working',
      timestamp: new Date().toISOString(),
      user: req.oidc.user.sub
    };
    
    console.log('Attempting to fetch clients...');
    const clients = await managementAPI.getClients({
      fields: 'client_id,name,app_type',
      include_fields: true
    });
    
    console.log(`Found ${clients.length} clients`);
    
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
    const allowedFields = ['name', 'email', 'username'];
    if (!allowedFields.includes(field)) {
      return res.redirect('/profile?error=Invalid field specified');
    }

    if (!value || value.trim().length === 0) {
      return res.redirect(`/profile?error=${field.charAt(0).toUpperCase() + field.slice(1)} cannot be empty`);
    }

    const trimmedValue = value.trim();

    if (field === 'name' && trimmedValue.length < 2) {
      return res.redirect('/profile?error=Name must be at least 2 characters long');
    }

    if (field === 'email' && !trimmedValue.includes('@')) {
      return res.redirect('/profile?error=Please enter a valid email address');
    }

    if (field === 'username' && !/^[a-zA-Z0-9_]+$/.test(trimmedValue)) {
      return res.redirect('/profile?error=Username can only contain letters, numbers, and underscores');
    }

    const currentUser = await managementAPI.getUser({ id: userId });
    const currentValue = currentUser[field];

    if (currentValue === trimmedValue) {
      return res.redirect(`/profile?success=${field.charAt(0).toUpperCase() + field.slice(1)} updated successfully`);
    }

    if (field === 'email') {
      try {
        const existingUsers = await managementAPI.getUsersByEmail(trimmedValue);
        const isEmailTaken = existingUsers.some(user => user.user_id !== userId);
        
        if (isEmailTaken) {
          return res.redirect('/profile?error=Email address is already in use');
        }
      } catch (emailCheckError) {
        console.error('Error checking email availability:', emailCheckError);
      }
    }

    const updateData = {};
    updateData[field] = trimmedValue;

    await managementAPI.updateUser({ id: userId }, updateData);
    
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

// Enhanced Apps Portal route with SSO
app.get('/apps', requiresAuth(), async (req, res) => {
  try {
    const userId = req.oidc.user.sub;
    const user = await managementAPI.getUser({ id: userId });

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

// Enhanced Application Launch with Token Generation - FIXED VERSION
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

    const ssoToken = generateSSOToken(req.oidc.user);
    const redirectUri = (client.callbacks && client.callbacks[0]) || `${process.env.BASE_URL}/apps`;
    
    let ssoUrl;
    let authMethod;
    
    switch(client.app_type) {
      case 'samlp':
        ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/samlp/${clientId}`;
        authMethod = 'saml';
        console.log(`Generated SAML SSO URL for ${client.name}`);
        break;
        
      case 'sso_integration':
        ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/authorize?` +
          `client_id=${clientId}&` +
          `response_type=code&` +
          `redirect_uri=${encodeURIComponent(redirectUri)}&` +
          `scope=openid profile email&` +
          `prompt=none&` +
          `state=${encodeURIComponent(JSON.stringify({ sso_token: ssoToken, source: 'portal', timestamp: Date.now() }))}`;
        authMethod = 'silent';
        console.log(`Generated SSO Integration URL for ${client.name}`);
        break;
        
      default:
        // Regular web applications with interactive login (FIXES the login_required error)
        ssoUrl = `https://${process.env.AUTH0_CUSTOM_DOMAIN}/authorize?` +
          `client_id=${clientId}&` +
          `response_type=code&` +
          `redirect_uri=${encodeURIComponent(redirectUri)}&` +
          `scope=openid profile email&` +
          `prompt=login&` +
          `state=${encodeURIComponent(JSON.stringify({ sso_token: ssoToken, source: 'portal', timestamp: Date.now() }))}`;
        authMethod = 'interactive';
        console.log(`Generated OAuth SSO URL for ${client.name} with interactive login`);
    }

    res.json({
      success: true,
      sso_url: ssoUrl,
      client_name: client.name,
      app_type: client.app_type,
      session_token: ssoToken,
      redirect_uri: redirectUri,
      auth_method: authMethod
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

// API endpoint to get all applications in the tenant
app.get('/api/applications', requiresAuth(), async (req, res) => {
  try {
    console.log('Fetching applications from Auth0...');
    
    const clients = await managementAPI.getClients({
      fields: 'client_id,name,description,app_type,logo_uri,callbacks,web_origins,client_metadata',
      include_fields: true
    });

    console.log(`Found ${clients.length} total clients`);

    const applications = clients
      .filter(client => {
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
        created_at: new Date().toISOString(),
        sso_disabled: false,
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
  
  if (!process.env.AUTH0_CUSTOM_DOMAIN) {
    console.error('❌ ERROR: AUTH0_CUSTOM_DOMAIN is required for login/logout functionality!');
  }
  if (!process.env.AUTH0_TENANT_DOMAIN) {
    console.error('❌ ERROR: AUTH0_TENANT_DOMAIN is required for Management API calls!');
  }
});

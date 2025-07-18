// index.js - Complete Enhanced Account Management Portal
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
  scope: 'read:users update:users delete:guardian_enrollments create:guardian_enrollment_tickets read:user_idp_tokens create:user_tickets'
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
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Error fetching user data for password change:', error);
    res.status(500).render('error', { message: 'Failed to load password change page' });
  }
});

// Direct Password Change endpoint (new method)
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
    
    // For Auth0 users (username-password connection), we need to verify current password
    if (user.user_id.startsWith('auth0|')) {
      try {
        // Attempt to authenticate with current credentials to verify current password
        const response = await fetch(`https://${process.env.AUTH0_TENANT_DOMAIN}/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            grant_type: 'password',
            username: user.email,
            password: currentPassword,
            client_id: process.env.AUTH0_CLIENT_ID,
            client_secret: process.env.AUTH0_CLIENT_SECRET,
            scope: 'openid profile email'
          })
        });

        if (!response.ok) {
          return res.redirect('/change-password?error=Current password is incorrect');
        }
      } catch (authError) {
        console.error('Password verification error:', authError);
        return res.redirect('/change-password?error=Unable to verify current password');
      }
    }

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

// Email-based Password Change endpoint (fallback method)
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
app.listen(PORT, () => {
  console.log(`Account Management Portal running on port ${PORT}`);
  console.log('Available at:', process.env.BASE_URL || `http://localhost:${PORT}`);
  console.log('Auth0 Configuration:');
  console.log('- Custom Domain:', process.env.AUTH0_CUSTOM_DOMAIN);
  console.log('- Tenant Domain:', process.env.AUTH0_TENANT_DOMAIN);
  console.log('- Management Client ID:', process.env.AUTH0_MGMT_CLIENT_ID ? 'SET' : 'NOT SET');
});

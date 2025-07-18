# Auth0 Account Management Portal

A comprehensive web application that provides users with a complete account management experience, similar to modern platforms like accounts.google.com. Users can manage their profile information, configure security settings, and handle multi-factor authentication through an intuitive interface.

## 🚀 Features

### 👤 Profile Management
- **Edit Profile Information**: Update name, email, and username with real-time validation
- **Account Overview**: View account statistics, creation date, and activity
- **Email Verification Status**: Visual indicators for email verification
- **Account Information**: Display user ID, connection type, and login statistics

### 🔒 Security Management
- **Multi-Factor Authentication**: Support for 5 different MFA methods
  - SMS Authentication
  - Email Authentication  
  - Auth0 Guardian App
  - Google Authenticator/TOTP
  - WebAuthn Security Keys
- **Security Level Assessment**: Visual security scoring based on active methods
- **MFA Method Management**: Add and remove security methods easily
- **Security Tips and Best Practices**: Guidance for account protection

### 🔑 Password Management
- **Secure Password Reset**: Email-based password change system
- **Password Security Tips**: Guidelines for creating strong passwords
- **Last Update Tracking**: Monitor when passwords were last changed

### 📊 Account Dashboard
- **Security Overview**: Visual representation of account security level
- **Quick Actions**: Fast access to common tasks
- **Activity Statistics**: Login count, active methods, and account age
- **Real-time Updates**: Dynamic content updates based on user actions

### 🎨 User Experience
- **Modern Design**: Clean, professional interface with Bootstrap 5
- **Responsive Layout**: Mobile-friendly design that works on all devices
- **Interactive Elements**: Smooth animations and hover effects
- **Real-time Validation**: Instant feedback on form inputs
- **Accessibility**: Proper contrast ratios and semantic markup

## 🛠️ Setup Instructions

### Prerequisites
- Node.js 18+ 
- Auth0 account
- Git repository (GitHub, GitLab, or Bitbucket)

### 1. Auth0 Configuration

#### Create Web Application
1. Go to Auth0 Dashboard → Applications
2. Create a new "Regular Web Application"
3. Note down: Domain, Client ID, Client Secret

#### Create Management API Application
1. Go to Applications → APIs → Auth0 Management API
2. Go to "Machine to Machine Applications" tab
3. Create a new M2M application
4. Grant these scopes:
   - `read:users`
   - `update:users` 
   - `delete:guardian_enrollments`
   - `create:guardian_enrollment_tickets`
   - `read:user_idp_tokens`

#### Enable MFA in Tenant
1. Go to Security → Multi-factor Auth
2. Enable desired factors: SMS, Email, Google Authenticator, Guardian, WebAuthn
3. Set policy to "Never" (managed through app)
4. Enable "Allow users to manage their own enrollments"

#### Configure Custom Domain (Optional)
1. Set up custom domain in Auth0
2. Update application URLs accordingly

### 2. Environment Variables

For **local development**:
```env
# Auth0 Application Settings
AUTH0_CUSTOM_DOMAIN=auth.yourdomain.com
AUTH0_TENANT_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
BASE_URL=http://localhost:3000

# Auth0 Management API Settings  
AUTH0_MGMT_CLIENT_ID=your-management-api-client-id
AUTH0_MGMT_CLIENT_SECRET=your-management-api-client-secret

# Session Secret
SESSION_SECRET=your-long-random-string-min-32-chars

# Server Port
PORT=3000
```

For **DigitalOcean deployment**:
- Replace `BASE_URL` with your app URL
- Use the same Auth0 credentials
- Update Auth0 application URLs to match deployment URL

### 3. Local Development

```bash
# Clone and install
git clone <your-repo>
cd auth0-account-management
npm install

# Configure environment
cp .env.example .env
# Edit .env with your Auth0 credentials

# Start development server
npm run dev
```

### 4. DigitalOcean Deployment

#### Update Auth0 URLs
Replace localhost URLs with your DigitalOcean app URL:
- **Allowed Callback URLs**: `https://your-app.ondigitalocean.app/callback`
- **Allowed Logout URLs**: `https://your-app.ondigitalocean.app`
- **Allowed Web Origins**: `https://your-app.ondigitalocean.app`

#### Deploy to App Platform
1. Connect your Git repository
2. Configure build settings:
   - **Build Command**: Leave empty
   - **Run Command**: `npm start`
   - **HTTP Port**: `3000`
3. Add environment variables (all from your .env file)
4. Deploy and test

## 📋 Usage Guide

### For End Users

1. **Access the Portal**: Visit your deployed URL
2. **Sign In**: Use Auth0 login
3. **Account Overview**: View dashboard with security stats
4. **Edit Profile**: Update personal information with real-time validation
5. **Configure Security**: Add/remove MFA methods as needed
6. **Change Password**: Request secure password reset via email
7. **Monitor Activity**: Track login history and account changes

### Navigation Structure
- **Overview**: Main dashboard with quick stats and actions
- **Profile**: Edit personal information and account details  
- **Security**: Manage MFA methods and view security level
- **Password**: Change password securely via email

## 🔧 Technical Details

### Architecture
- **Backend**: Express.js with Auth0 SDK
- **Frontend**: EJS templates with Bootstrap 5
- **Authentication**: Auth0 OpenID Connect
- **MFA Management**: Auth0 Management API
- **Session Storage**: Express sessions (memory store)

### Key Components
- **Profile Management**: Real-time validation, email availability checking
- **Security Dashboard**: Dynamic security level calculation
- **MFA Integration**: Support for multiple authentication methods
- **Password Management**: Secure email-based reset flow

### Security Features
- **CSRF Protection**: Session-based security
- **Input Validation**: Client and server-side validation
- **Secure Headers**: Proper security headers implementation
- **Rate Limiting**: Built-in Auth0 rate limiting

## 🚨 Important Security Notes

### Management API Domain
- **Custom Domain**: Use for user authentication (login/logout)
- **Tenant Domain**: Required for Management API calls
- **Never Mix**: Custom domains don't work with Management API

### Environment Variables
- **Secrets**: Use "Encrypted" type in DigitalOcean for sensitive values
- **Validation**: Ensure all required variables are set
- **Separation**: Keep custom domain and tenant domain separate

### Account Deletion
- **Permanent Action**: Cannot be undone
- **Data Loss**: All user data is permanently deleted
- **Safety Measures**: Multiple confirmation steps required

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## 💡 Future Enhancements

- [ ] Account deactivation option
- [ ] Export user data functionality
- [ ] Advanced login history with IP tracking
- [ ] Email notification preferences
- [ ] API access token management
- [ ] Social account linking/unlinking
- [ ] Advanced security alerts
- [ ] Account recovery options

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section below
2. Review Auth0 documentation
3. Open an issue on GitHub

## 🔍 Troubleshooting

### Common Issues

**"Service not enabled within domain" Error**
- Ensure `AUTH0_TENANT_DOMAIN` uses your Auth0 tenant domain (not custom domain)
- Verify Management API credentials are correct

**Login Redirects to Wrong URL**
- Check callback URLs in Auth0 application settings
- Verify `BASE_URL` environment variable matches your deployment URL

**MFA Methods Not Loading**
- Confirm Management API has required scopes
- Check that MFA factors are enabled in Auth0 tenant

**Real-time Validation Not Working**
- Verify API endpoints are accessible
- Check browser console for JavaScript errors

**Session Issues**
- Ensure `SESSION_SECRET` is set and sufficiently random
- Check session configuration in Express setup

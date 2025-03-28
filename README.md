# Auth0 MFA Management Portal

A web application that allows users to manage their Auth0 multi-factor authentication methods.

## Features

- View all enrolled MFA methods
- Add new MFA methods (SMS, Email, Guardian App, Google Authenticator, Security Key)
- Remove existing MFA methods
- Secure authentication with Auth0

## Setup

1. Clone this repository
2. Create a `.env` file with the required Auth0 credentials
3. Run `npm install` to install dependencies
4. Run `npm start` to start the server

## Environment Variables

- `AUTH0_DOMAIN`: Your Auth0 tenant domain
- `AUTH0_CLIENT_ID`: Your Auth0 application client ID
- `AUTH0_CLIENT_SECRET`: Your Auth0 application client secret
- `BASE_URL`: The base URL of your application
- `AUTH0_MGMT_CLIENT_ID`: Your Auth0 Management API client ID
- `AUTH0_MGMT_CLIENT_SECRET`: Your Auth0 Management API client secret
- `SESSION_SECRET`: A long random string for session security
- `PORT`: The port to run the server on (default: 3000)

## Auth0 Configuration

1. Enable multiple MFA enrollments in your Auth0 tenant
2. Create a Management API client with the required permissions
3. Update the allowed callbacks and logout URLs in your Auth0 application

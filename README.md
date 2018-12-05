
# auth-service-prodio

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

`auth-service-prodio` is a simple service to handle auth user journeys. It supports both email based auth and mobile otp based auth.

# Features!
1. Signup/Register Account
2. Verify Account 
3. Regenerate OTP/verification token
4. Login
5. List Accounts
6. Forgot Password
7. Reset Password
8. Unregister/Deactivate Account


# Installation
1. Clone this repository on your server `git clone https://github.com/ProdioDesignWorks/auth-service-prodio.git`
2. Navigate to your repo `cd auth-service-prodio`
3. Install dependencies `npm install`
4. Start service `node .` or `npm start` or `node server/server.js`
5. Open `http://localhost:3005/explorer/` in your browser
5. If you've pm2 installed then use this `pm2 start server/server.js --name="AUTH_SERVICE"`
#### NOTE: 
`auth-service-prodio` uses loopback as the core framework for developing API's, so all customisations, configurations, middlewares and db connectors can be used which you would have used in loopback.

# Configuration
Open `config.js` file in the `config` folder. Auth service provides 4 configuration option as below: 

1. authType(String) - can be one of `EMAIL` for email, password based auth or `OTP` for mobile otp based auth.
2. otpDigits(Integer) - Mandatory for OTP based auth. Number of digits of otp to be generated if OTP based auth.
3. encryptionKey(String) - Mandatory for EMAIL based auth. Secured key using which the password and verification tokens are to be encrypted.
4. securedPassword(Boolean) - Mandatory for EMAIL based auth. If set to true all passwords will be checked to have minimum 8 characters, combination of uppercase, lowercase, number and special characters.


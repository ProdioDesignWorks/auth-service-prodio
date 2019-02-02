const googleCredentials = require('./google-credentials.json');

const {
	client_id: clientId,
	client_secret: clientSecret,
	redirect_uris: redirect,
} = googleCredentials.web;

/**
 * This object holds all google configuration's
 */
const googleConfig = { 
	clientId, 
	clientSecret, 
	redirect
};

//http://localhost:3005/api/authAccounts/googleSignIn
//"https://trade.tradewizer.com/auth/google-signin"

/**
 * This scope tells google what information we want to request.
 */
const defaultScope = [
  'https://www.googleapis.com/auth/plus.me',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

exports.googleConfig = googleConfig;
exports.defaultScope = defaultScope;
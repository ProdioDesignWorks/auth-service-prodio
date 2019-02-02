const { google } = require('googleapis');
const path = require('path');
const { googleConfig, defaultScope } = require(
	path.resolve(__dirname, '../config/google-config')
);

function GoogleClient(googleConfig, defaultScope){
	this.googleConfig = googleConfig;
	this.defaultScope = defaultScope;
	this.OAuth2Client = null;

	/**
	 * Create the google auth object which gives us access to talk to google's apis.
	 */
	this.createConnection = () => {
		if(this.OAuth2Client){
			return this.OAuth2Client;
		}
		return new google.auth.OAuth2(
			this.googleConfig.clientId, 
			this.googleConfig.clientSecret, 
			this.googleConfig.redirect
		);
	};

	/**
	 * Get a url which will open the google sign-in page and request access to the scope provided (such as calendar events).
	 */
	this.getConnectionUrl = () => (
		this.OAuth2Client.generateAuthUrl({
			access_type: 'offline',
			prompt: 'consent', // access type and approval prompt will force a new refresh token to be made each time signs in
			scope: this.defaultScope,
		})
	);

	/**
	 * Create the google url to be sent to the client.
	 */
	this.googleAuthUrl = () => this.getConnectionUrl();

	this.verifyToken = async (code) => {
		const data = await this.OAuth2Client.getToken(code);
		const { id_token } = data.tokens;

		const ticket = await this.OAuth2Client.verifyIdToken({
	      	idToken: id_token,
	      	audience: this.googleConfig.clientId,
	  	});

		const payload = ticket.getPayload();

		const { email, email_verified, aud, sub: id, azp, name, picture = '' } = payload;

		if(aud !== this.googleConfig.clientId){
			throw new Error('Client ID different from google APP client ID');
		}

		return { email, email_verified, id, name, picture };
	};
	
	/**
	 * Initializes lib
	 */
	this.initialiaze = () => (this.OAuth2Client = this.createConnection(), this.OAuth2Client);

	this.initialiaze();
};


/**
 * Exports
 */
exports.GoogleClient = ( new GoogleClient(googleConfig, defaultScope) );
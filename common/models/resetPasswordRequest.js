'use strict';
const HttpErrors = require('http-errors');
const bcrypt = require('bcrypt');
const moment = require('moment');

const {
    authType, otpDigits, encryptionKey, securedPassword
} = require('../../config/config');
const {
    emailAuthType, otpAuthType, saltRounds, SELF_SIGNUP, GOOGLE_SIGNUP,mobileEmailAuthType
} = require('../../utility/constants');
const {
    isNullValue, isValidEmail, isValidPhoneNumber, isPasswordSecured, getFormattedEmail, generateVerificationToken, verifyToken
} = require('../../utility/helper');
const { GoogleClient } = require('../../google/google.js');



module.exports = function (ResetPasswordRequests) {

}
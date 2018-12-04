const authType = "OTP"; //EMAIL or OTP based login
const otpDigits = 4; //number of digits for otp
const encryptionKey = "authSecretKey"; //secret key for data encryption
const securedPassword = true; //secured password validations

exports.authType = authType;
exports.otpDigits = otpDigits;
exports.encryptionKey = encryptionKey;
exports.securedPassword =securedPassword;
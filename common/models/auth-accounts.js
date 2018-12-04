'use strict';
const HttpErrors = require('http-errors');
const bcrypt = require('bcrypt');
const moment = require('moment');

const {
    authType, otpDigits, encryptionKey, securedPassword
} = require('../../config/config');
const {
    emailAuthType, otpAuthType, saltRounds
} = require('../../utility/constants');
const {
    isNullValue, isValidEmail, isValidPhoneNumber, isPasswordSecured, getFormattedEmail, generateVerificationToken, verifyToken
} = require('../../utility/helper');

module.exports = function (Authaccounts) {

    Authaccounts.remoteMethod(
        'registerAccount', {
            http: {
                path: '/register',
                verb: 'post'
            },
            description: ["creates a new account."],
            accepts: [{
                arg: 'account',
                type: 'authAccounts',
                required: true,
                http: {
                    source: 'body'
                }
            }],
            returns: {
                type: 'object',
                root: true
            }
        }
    );

    Authaccounts.remoteMethod(
        'verifyAccount', {
            http: {
                path: '/verify',
                verb: 'post'
            },
            description: ["verifies an account."],
            accepts: [{
                arg: 'data',
                type: 'object',
                required: true,
                http: {
                    source: 'body'
                }
            }],
            returns: {
                type: 'object',
                root: true
            }
        }
    );

    Authaccounts.remoteMethod(
        'regenerateToken', {
            http: {
                path: '/tokenRequest',
                verb: 'post'
            },
            description: ["generates a new verification token for an account."],
            accepts: [{
                arg: 'data',
                type: 'object',
                required: true,
                http: {
                    source: 'body'
                }
            }],
            returns: {
                type: 'object',
                root: true
            }
        }
    );

    Authaccounts.registerAccount = (account, cb) => {
        if (authType === emailAuthType) {
            if (!isNullValue(encryptionKey)) {
                if (isNullValue(account.email)) {
                    return cb(new HttpErrors.BadRequest('Email address is mandatory.', { expose: false }))
                } else if (isNullValue(account.password)) {
                    return cb(new HttpErrors.BadRequest('Password is mandatory.', { expose: false }))
                } else if (!isValidEmail(account.email)) {
                    return cb(new HttpErrors.BadRequest('Invalid Email address.', { expose: false }))
                } else if (securedPassword && !isPasswordSecured(account.password)) {
                    return cb(new HttpErrors.BadRequest('Password must have minimum 8 characters, combination of uppercase, lowercase, number and special characters.', { expose: false }))
                } else {
                    const email = getFormattedEmail(account.email);
                    const password = account.password.trim();
                    const findEmail = {
                        where: {
                            and: [
                                { email: email },
                                { isDeleted: false }
                            ]
                        }
                    }
                    Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
                        if (findEmailErr) {
                            return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                        } else if (!isNullValue(accountData)) {
                            return cb(new HttpErrors.Conflict("Email address is already registered.", { expose: false }));
                        } else {
                            const accountJson = {
                                email: email,
                                password: bcrypt.hashSync(password, bcrypt.genSaltSync(saltRounds)),
                                createdAt: new Date()
                            }
                            Authaccounts.create(accountJson, (createErr, accountDetails) => {
                                if (createErr) {
                                    return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                                } else {
                                    const verificationToken = generateVerificationToken(accountDetails, encryptionKey);
                                    accountDetails.verificationToken = verificationToken;
                                    return cb(null, accountDetails);
                                }
                            });
                        }
                    });
                }
            } else {
                return cb(new HttpErrors.BadRequest('Encryption Key is not set.', { expose: false }))
            }
        } else if (authType === otpAuthType) {
            if (otpDigits > 0) {
                if (isNullValue(account.phone)) {
                    return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', { expose: false }))
                } else if (!isValidPhoneNumber(account.phone)) {
                    return cb(new HttpErrors.BadRequest('Invalid Mobile number.', { expose: false }))
                } else {
                    const phone = account.phone.trim();
                    const findPhone = {
                        where: {
                            and: [
                                { phone: phone },
                                { isDeleted: false }
                            ]
                        }
                    }
                    Authaccounts.findOne(findPhone, (findPhoneErr, accountData) => {
                        if (findPhoneErr) {
                            return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                        } else if (!isNullValue(accountData)) {
                            return cb(new HttpErrors.Conflict("Mobile number is already registered.", { expose: false }));
                        } else {
                            const accountJson = {
                                phone: phone,
                                otp: Math.floor(Math.pow(10, otpDigits - 1) + Math.random() * (Math.pow(10, otpDigits) - Math.pow(10, otpDigits - 1) - 1)),
                                otpGeneratedAt: new Date(),
                                createdAt: new Date()
                            }
                            Authaccounts.create(accountJson, (createErr, accountDetails) => {
                                if (createErr) {
                                    return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                                } else {
                                    return cb(null, accountDetails);
                                }
                            });
                        }
                    });
                }
            } else {
                return cb(new HttpErrors.BadRequest('Length of OTP should greater than zero.', { expose: false }))
            }
        } else {
            return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', { expose: false }))
        }
    }

    Authaccounts.verifyAccount = (data, cb) => {
        if (authType === emailAuthType) {
            if (!isNullValue(encryptionKey)) {
                if (isNullValue(data.verificationToken)) {
                    return cb(new HttpErrors.BadRequest('Verification token is mandatory.', { expose: false }))
                } else {
                    const decryptedToken = verifyToken(data.verificationToken, encryptionKey);
                    if (decryptedToken) {
                        const email = decryptedToken[0];
                        const id = decryptedToken[1];
                        const ts = decryptedToken[2];
                        var startDate = moment(new Date(ts), 'YYYY-M-DD HH:mm:ss');
                        var endDate = moment(new Date(), 'YYYY-M-DD HH:mm:ss');
                        var secondsDiff = endDate.diff(startDate, 'seconds');
                        if (secondsDiff > 900) { //15 min
                            return cb(new HttpErrors.NotAcceptable('Token expired.', { expose: false }))
                        } else {
                            const findAccount = {
                                where: {
                                    and: [
                                        { email: email },
                                        { id: id },
                                        { isDeleted: false }
                                    ]
                                }
                            }
                            Authaccounts.findOne(findAccount, (findErr, accountDetails) => {
                                if (findErr) {
                                    return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                                } else if (isNullValue(accountDetails)) {
                                    return cb(new HttpErrors.Forbidden("Email address not registered.", { expose: false }));
                                } else {
                                    const updateJson = {
                                        isVerified: true,
                                        updatedAt: new Date()
                                    }
                                    accountDetails.updateAttributes(updateJson, (updateErr, accountData) => {
                                        if (updateErr) {
                                            return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                                        } else {
                                            const returnObj = {
                                                message: "Account verified successfully."
                                            }
                                            return cb(null, returnObj);
                                        }
                                    });
                                }
                            });
                        }
                        return cb(null, data);
                    } else {
                        return cb(new HttpErrors.BadRequest('Invalid verification token.', { expose: false }))
                    }
                }
            } else {
                return cb(new HttpErrors.BadRequest('Encryption Key is not set.', { expose: false }))
            }
        } else if (authType === otpAuthType) {
            if (isNullValue(data.otp)) {
                return cb(new HttpErrors.BadRequest('OTP is mandatory.', { expose: false }))
            } else if (isNullValue(data.phone)) {
                return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', { expose: false }))
            } else {
                const findObj = {
                    where: {
                        and: [
                            { phone: data.phone },
                            { isDeleted: false }
                        ]
                    }
                }
                Authaccounts.findOne(findObj, (findErr, accountDetails) => {
                    if (findErr) {
                        return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                    } else if (isNullValue(accountDetails)) {
                        return cb(new HttpErrors.Forbidden("Mobile number not registered.", { expose: false }));
                    } else {
                        if (accountDetails.otp === data.otp) {
                            var startDate = moment(new Date(accountDetails.otpGeneratedAt), 'YYYY-M-DD HH:mm:ss');
                            var endDate = moment(new Date(), 'YYYY-M-DD HH:mm:ss');
                            var secondsDiff = endDate.diff(startDate, 'seconds');
                            if (secondsDiff > 900) {
                                return cb(new HttpErrors.NotAcceptable('OTP expired.', { expose: false }))
                            } else {
                                const updateJson = {
                                    otp: '',
                                    isVerified: true,
                                    updatedAt: new Date()
                                }
                                accountDetails.updateAttributes(updateJson, (updateErr, accountData) => {
                                    if (updateErr) {
                                        return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                                    } else {
                                        const returnObj = {
                                            message: "Account verified successfully."
                                        }
                                        return cb(null, returnObj);
                                    }
                                });
                            }
                        } else {
                            return cb(new HttpErrors.BadRequest('Invalid OTP.', { expose: false }))
                        }
                    }
                });
            }
        } else {
            return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', { expose: false }))
        }
    }

    Authaccounts.regenerateToken = (data, cb) => {
        if (authType === emailAuthType) {
            if (!isNullValue(encryptionKey)) {
                if (isNullValue(data.email)) {
                    return cb(new HttpErrors.BadRequest('Email address is mandatory.', { expose: false }))
                } else {
                    const email = getFormattedEmail(data.email);
                    const findEmail = {
                        where: {
                            and: [
                                { email: email },
                                { isDeleted: false }
                            ]
                        }
                    }
                    Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
                        if (findEmailErr) {
                            return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                        } else if (isNullValue(accountData)) {
                            return cb(new HttpErrors.BadRequest("Email address is not registered.", { expose: false }));
                        } else {
                            if (accountData.isVerified) {
                                return cb(new HttpErrors.Conflict("Email address is already verified.", { expose: false }));
                            } else {
                                let returnObj = {};
                                const verificationToken = generateVerificationToken(accountData, encryptionKey);
                                returnObj.verificationToken = verificationToken;
                                return cb(null, returnObj);
                            }
                        }
                    });
                }
            } else {
                return cb(new HttpErrors.BadRequest('Encryption Key is not set.', { expose: false }))
            }
        } else if (authType === otpAuthType) {
            if (otpDigits > 0) {
                if (isNullValue(data.phone)) {
                    return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', { expose: false }))
                } else {
                    const phone = data.phone.trim();
                    const findPhone = {
                        where: {
                            and: [
                                { phone: phone },
                                { isDeleted: false }
                            ]
                        }
                    }
                    Authaccounts.findOne(findPhone, (findPhoneErr, accountData) => {
                        if (findPhoneErr) {
                            return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                        } else if (isNullValue(accountData)) {
                            return cb(new HttpErrors.Conflict("Mobile number is not registered.", { expose: false }));
                        } else {
                            const otp = Math.floor(Math.pow(10, otpDigits - 1) + Math.random() * (Math.pow(10, otpDigits) - Math.pow(10, otpDigits - 1) - 1));
                            const accountJson = {
                                otp: otp,
                                otpGeneratedAt: new Date(),
                                updatedAt: new Date()
                            }
                            accountData.updateAttributes(accountJson, (updateErr, accountDetails) => {
                                if (updateErr) {
                                    return cb(new HttpErrors.InternalServerError("Please try again.", { expose: false }));
                                } else {
                                    const returnObj = {
                                        message: 'OTP generated successfully.',
                                        otp: otp
                                    }
                                    return cb(null, returnObj);
                                }
                            });
                        }
                    });
                }
            } else {
                return cb(new HttpErrors.BadRequest('Length of OTP should greater than zero.', { expose: false }))
            }
        } else {
            return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', { expose: false }))
        }
    }
};

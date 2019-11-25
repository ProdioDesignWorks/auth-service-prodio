'use strict';
const HttpErrors = require('http-errors');
const bcrypt = require('bcrypt');
const moment = require('moment');

const {
  authType,
  otpDigits,
  encryptionKey,
  securedPassword
} = require('../../config/config');
const {
  emailAuthType,
  otpAuthType,
  saltRounds,
  SELF_SIGNUP,
  GOOGLE_SIGNUP,
  mobileEmailAuthType
} = require('../../utility/constants');
const {
  isNullValue,
  isValidEmail,
  isValidPhoneNumber,
  isPasswordSecured,
  getFormattedEmail,
  generateVerificationToken,
  verifyToken,
  getJWTToken,
  verifyJwtToken
} = require('../../utility/helper');
const {
  GoogleClient
} = require('../../google/google.js');


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

  Authaccounts.remoteMethod(
    'login', {
      http: {
        path: '/login',
        verb: 'post'
      },
      description: ["login request."],
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
    'list', {
      http: {
        path: '/accounts',
        verb: 'get'
      },
      description: ["List of all accounts."],
      accepts: [],
      returns: {
        type: 'object',
        root: true
      }
    }
  );

  Authaccounts.remoteMethod(
    'resetPassword', {
      http: {
        path: '/resetPassword',
        verb: 'post'
      },
      description: ["Reset password based on the token."],
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
    'changePassword', {
      http: {
        path: '/changePassword',
        verb: 'post'
      },
      description: ["Change account password."],
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
    'unregister', {
      http: {
        path: '/unregister',
        verb: 'post'
      },
      description: ["deletes an existing account."],
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
    'googleSignInUrl', {
      http: {
        path: '/googleSignInUrl',
        verb: 'get'
      },
      description: ["Generates Url for google signin"],
      accepts: [{
        arg: 'state',
        type: 'string',
        required: false,
        http: {
          source: 'query'
        }
      }],
      returns: {
        type: 'string',
        root: true
      }
    }
  );

  Authaccounts.remoteMethod(
    'googleSignIn', {
      http: {
        path: '/googleSignIn',
        verb: 'get'
      },
      description: ["Google Signin."],
      accepts: [{
        arg: 'code',
        type: 'string',
        required: true,
        http: {
          source: 'query'
        }
      }, {
        arg: 'scope',
        type: 'string',
        required: true,
        http: {
          source: 'query'
        }
      }, {
        arg: 'res',
        type: 'object',
        http: ctx => {
          return ctx.res;
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
          return cb(new HttpErrors.BadRequest('Email address is mandatory.', {
            expose: false
          }))
        } else if (isNullValue(account.password)) {
          return cb(new HttpErrors.BadRequest('Password is mandatory.', {
            expose: false
          }))
        } else if (!isValidEmail(account.email)) {
          return cb(new HttpErrors.BadRequest('Invalid Email address.', {
            expose: false
          }))
        } else if (securedPassword && !isPasswordSecured(account.password)) {
          return cb(new HttpErrors.BadRequest('Password must have minimum 8 characters, combination of uppercase, lowercase, number and special characters.', {
            expose: false
          }))
        } else {
          const email = getFormattedEmail(account.email);
          const password = account.password.trim();
          const findEmail = {
            where: {
              and: [{
                  email: email
                },
                {
                  isDeleted: false
                }
              ]
            }
          }
          Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
            if (findEmailErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (!isNullValue(accountData)) {
              return cb(new HttpErrors.Conflict("Email address is already registered.", {
                expose: false
              }));
            } else {
              const accountJson = {
                email: email,
                password: bcrypt.hashSync(password, bcrypt.genSaltSync(saltRounds)),
                userType: SELF_SIGNUP,
                createdAt: new Date()
              }
              Authaccounts.create(accountJson, (createErr, accountDetails) => {
                if (createErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
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
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else if (authType === otpAuthType) {
      if (otpDigits > 0) {
        if (isNullValue(account.phone)) {
          return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', {
            expose: false
          }))
        } else if (!isValidPhoneNumber(account.phone)) {
          return cb(new HttpErrors.BadRequest('Invalid Mobile number.', {
            expose: false
          }))
        } else {
          const phone = account.phone.trim();
          const findPhone = {
            where: {
              and: [{
                  phone: phone
                },
                {
                  isDeleted: false
                }
              ]
            }
          }
          Authaccounts.findOne(findPhone, (findPhoneErr, accountData) => {
            if (findPhoneErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (!isNullValue(accountData)) {
              return cb(new HttpErrors.Conflict("Mobile number is already registered.", {
                expose: false
              }));
            } else {
              const accountJson = {
                phone: phone,
                otp: Math.floor(Math.pow(10, otpDigits - 1) + Math.random() * (Math.pow(10, otpDigits) - Math.pow(10, otpDigits - 1) - 1)),
                otpGeneratedAt: new Date(),
                createdAt: new Date()
              }
              Authaccounts.create(accountJson, (createErr, accountDetails) => {
                if (createErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
                } else {
                  return cb(null, accountDetails);
                }
              });
            }
          });
        }
      } else {
        return cb(new HttpErrors.BadRequest('Length of OTP should greater than zero.', {
          expose: false
        }))
      }
    } else if (authType === mobileEmailAuthType) {
      /** To validate Registration for mobile and password based.
       ie authentication has to be mobile based but login can be done using mobile or email
       */
      const {
        phone,
        email = '',
        password = ''
      } = account;

      if (isNullValue(phone)) {
        return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', {
          expose: false
        }))
      }

      if (!isValidPhoneNumber(phone)) {
        return cb(new HttpErrors.BadRequest('Invalid Mobile number.', {
          expose: false
        }))
      }

      if (isNullValue(password)) {
        return cb(new HttpErrors.BadRequest('Password is mandatory.', {
          expose: false
        }))
      }

      if (securedPassword && !isPasswordSecured(password)) {
        return cb(new HttpErrors.BadRequest('Password must have minimum 8 characters, combination of uppercase, lowercase, number and special characters.', {
          expose: false
        }))
      }

      if (email && !isValidEmail(email)) {
        return cb(new HttpErrors.BadRequest('Invalid Email address.', {
          expose: false
        }))
      }

      const findPhone = {
        where: {
          and: [{
              phone: phone.trim()
            },
            {
              isDeleted: false
            }
          ]
        }
      };

      Authaccounts.findOne(findPhone, (findPhoneErr, accountData) => {
        if (findPhoneErr) {
          return cb(new HttpErrors.InternalServerError("Please try again.", {
            expose: false
          }));
        } else if (!isNullValue(accountData)) {
          return cb(new HttpErrors.Conflict("Mobile number is already registered.", {
            expose: false
          }));
        } else {
          const accountJson = {
            phone: phone.trim(),
            email: email,
            password: bcrypt.hashSync(password, bcrypt.genSaltSync(saltRounds)),
            createdAt: new Date(),
            isVerified: true
          };

          Authaccounts.create(accountJson, (createErr, accountDetails) => {
            if (createErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else {
              return cb(null, accountDetails);
            }
          });
        }
      });
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.verifyAccount = (data, cb) => {
    if (authType === emailAuthType) {
      if (!isNullValue(encryptionKey)) {
        if (isNullValue(data.verificationToken)) {
          return cb(new HttpErrors.BadRequest('Verification token is mandatory.', {
            expose: false
          }))
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
              return cb(new HttpErrors.NotAcceptable('Token expired.', {
                expose: false
              }))
            } else {
              const findAccount = {
                where: {
                  and: [{
                      email: email
                    },
                    {
                      id: id
                    },
                    {
                      isDeleted: false
                    }
                  ]
                }
              }
              Authaccounts.findOne(findAccount, (findErr, accountDetails) => {
                if (findErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
                } else if (isNullValue(accountDetails)) {
                  return cb(new HttpErrors.Forbidden("Email address not registered.", {
                    expose: false
                  }));
                } else {
                  const updateJson = {
                    isVerified: true,
                    updatedAt: new Date()
                  }
                  accountDetails.updateAttributes(updateJson, (updateErr, accountData) => {
                    if (updateErr) {
                      return cb(new HttpErrors.InternalServerError("Please try again.", {
                        expose: false
                      }));
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
          } else {
            return cb(new HttpErrors.BadRequest('Invalid verification token.', {
              expose: false
            }))
          }
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else if (authType === otpAuthType) {
      if (isNullValue(data.otp)) {
        return cb(new HttpErrors.BadRequest('OTP is mandatory.', {
          expose: false
        }))
      } else if (isNullValue(data.phone)) {
        return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', {
          expose: false
        }))
      } else {
        const findObj = {
          where: {
            and: [{
                phone: data.phone
              },
              {
                isDeleted: false
              }
            ]
          }
        }
        Authaccounts.findOne(findObj, (findErr, accountDetails) => {
          if (findErr) {
            return cb(new HttpErrors.InternalServerError("Please try again.", {
              expose: false
            }));
          } else if (isNullValue(accountDetails)) {
            return cb(new HttpErrors.Forbidden("Mobile number not registered.", {
              expose: false
            }));
          } else {
            if (accountDetails.otp === data.otp) {
              var startDate = moment(new Date(accountDetails.otpGeneratedAt), 'YYYY-M-DD HH:mm:ss');
              var endDate = moment(new Date(), 'YYYY-M-DD HH:mm:ss');
              var secondsDiff = endDate.diff(startDate, 'seconds');
              if (secondsDiff > 900) {
                return cb(new HttpErrors.NotAcceptable('OTP expired.', {
                  expose: false
                }))
              } else {
                const updateJson = {
                  otp: '',
                  isVerified: true,
                  updatedAt: new Date()
                }
                accountDetails.updateAttributes(updateJson, (updateErr, accountData) => {
                  if (updateErr) {
                    return cb(new HttpErrors.InternalServerError("Please try again.", {
                      expose: false
                    }));
                  } else {
                    const returnObj = {
                      message: "OTP verified successfully."
                    }
                    return cb(null, returnObj);
                  }
                });
              }
            } else {
              return cb(new HttpErrors.BadRequest('Invalid OTP.', {
                expose: false
              }))
            }
          }
        });
      }
    } else if (authType === mobileEmailAuthType) {
      const {
        otp = '', token = '', phone = ''
      } = data

      if (!otp) {
        return cb(new HttpErrors.BadRequest('OTP is mandatory.', {
          expose: false
        }))
      } else if (!phone) {
        return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', {
          expose: false
        }))
      } else if (!isValidPhoneNumber(phone)) {
        return cb(new HttpErrors.BadRequest('Invalid Mobile number.', {
          expose: false
        }))
      } else {
        const findObj = {
          where: {
            and: [{
              phone: phone
            }]
          }
        }
        Authaccounts.app.models.authenticateRequest.findOne(findObj, (findErr, accountDetails) => {
          if (findErr) {
            return cb(new HttpErrors.InternalServerError("Please try again.", {
              expose: false
            }));
          } else if (isNullValue(accountDetails)) {
            return cb(new HttpErrors.Forbidden("Mobile number or Email not registered.", {
              expose: false
            }));
          } else {
            if (accountDetails.otp === otp) {
              var decoded = verifyJwtToken(token);

              if (decoded) {
                return cb(null, accountDetails);
              } else {
                return cb(new HttpErrors.BadRequest('Invalid Token.', {
                  expose: false
                }))

              }
            } else {
              return cb(new HttpErrors.BadRequest('Invalid OTP.', {
                expose: false
              }))
            }
          }
        });
      }
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.regenerateToken = (data, cb) => {

    if (authType === emailAuthType) {
      if (!isNullValue(encryptionKey)) {
        if (isNullValue(data.email)) {
          return cb(new HttpErrors.BadRequest('Email address is mandatory.', {
            expose: false
          }))
        } else if (!isValidEmail(data.email)) {
          return cb(new HttpErrors.BadRequest('Invalid Email address.', {
            expose: false
          }))
        } else {
          const email = getFormattedEmail(data.email);
          const findEmail = {
            where: {
              and: [{
                email: email
              }]
            }
          }
          Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
            if (findEmailErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (isNullValue(accountData)) {
              return cb(new HttpErrors.BadRequest("Email address is not registered.", {
                expose: false
              }));
            } else {
              let returnObj = {};
              const verificationToken = generateVerificationToken(accountData, encryptionKey);
              returnObj.verificationToken = verificationToken;
              return cb(null, returnObj);
            }
          });
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else if (authType === otpAuthType) {
      if (otpDigits > 0) {
        if (isNullValue(data.phone)) {
          return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', {
            expose: false
          }))
        } else if (!isValidPhoneNumber(account.phone)) {
          return cb(new HttpErrors.BadRequest('Invalid Mobile number.', {
            expose: false
          }))
        } else {
          const phone = data.phone.trim();
          const findPhone = {
            where: {
              and: [{
                  phone: phone
                },
                {
                  isDeleted: false
                }
              ]
            }
          }
          Authaccounts.findOne(findPhone, (findPhoneErr, accountData) => {
            if (findPhoneErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (isNullValue(accountData)) {
              return cb(new HttpErrors.Conflict("Mobile number is not registered.", {
                expose: false
              }));
            } else {
              const otp = Math.floor(Math.pow(10, otpDigits - 1) + Math.random() * (Math.pow(10, otpDigits) - Math.pow(10, otpDigits - 1) - 1));
              const accountJson = {
                otp: otp,
                otpGeneratedAt: new Date(),
                updatedAt: new Date()
              }
              accountData.updateAttributes(accountJson, (updateErr, accountDetails) => {
                if (updateErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
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
        return cb(new HttpErrors.BadRequest('Length of OTP should greater than zero.', {
          expose: false
        }))
      }
    } else if (authType === mobileEmailAuthType) {
      const {
        phone = ''
      } = data;

      if (!isNullValue(encryptionKey)) {
        if (isNullValue(phone)) {
          return cb(new HttpErrors.BadRequest('phone number is mandatory.', {
            expose: false
          }))
        } else if (!isValidPhoneNumber(phone)) {
          return cb(new HttpErrors.BadRequest('Invalid phone address.', {
            expose: false
          }))
        } else {

          const findquery = {
            where: {
              and: [{
                phone: phone,
                isDeleted: false
              }]
            }
          }
          Authaccounts.findOne(findquery, (findEmailErr, accountData) => {
            if (findEmailErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (isNullValue(accountData)) {
              return cb(new HttpErrors.BadRequest("Email address is not registered.", {
                expose: false
              }));
            } else {
              let returnObj = {};
              let {
                phone = '', email = ''
              } = accountData
              const verificationToken = getJWTToken(accountData);
              returnObj.verificationToken = verificationToken;

              const otp = Math.floor(Math.pow(10, otpDigits - 1) + Math.random() * (Math.pow(10, otpDigits) - Math.pow(10, otpDigits - 1) - 1));

              const accountJson = {
                otp: otp,
                token: verificationToken,
                updated: new Date(),
                phone: phone,
                email: email

              }

              const queryData = {
                and: [{
                    "phone": phone
                  },
                  {
                    "email": email
                  }
                ]
              }


              Authaccounts.app.models.authenticateRequest.upsertWithWhere(queryData, accountJson, (createErr, accountDetails) => {
                if (createErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
                } else {
                  // const verificationToken = generateVerificationToken(accountDetails, encryptionKey);
                  // accountDetails.verificationToken = verificationToken;
                  return cb(null, accountDetails);
                }
              });
              // return cb(null, returnObj);
            }
          });
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.login = (data, cb) => {
    if (authType === emailAuthType) {
      if (!isNullValue(encryptionKey)) {
        if (isNullValue(data.email)) {
          return cb(new HttpErrors.BadRequest('Email address is mandatory.', {
            expose: false
          }))
        } else if (!isValidEmail(data.email)) {
          return cb(new HttpErrors.BadRequest('Invalid Email address.', {
            expose: false
          }))
        } else if (isNullValue(data.password)) {
          return cb(new HttpErrors.BadRequest('Password is mandatory.', {
            expose: false
          }))
        } else {
          const email = getFormattedEmail(data.email);
          const password = data.password.trim();
          const findEmail = {
            where: {
              and: [{
                  email: email
                },
                {
                  isDeleted: false
                }
              ]
            }
          }
          Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
            if (findEmailErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (isNullValue(accountData)) {
              return cb(new HttpErrors.Conflict("Email address is not registered.", {
                expose: false
              }));
            } else {
              if (accountData.isVerified) {
                if (bcrypt.compareSync(password, accountData.password)) {
                  const loginResp = {
                    id: accountData.id,
                    email: accountData.email,
                    createdAt: accountData.createdAt
                  }
                  return cb(null, loginResp)
                } else {
                  return cb(new HttpErrors.Forbidden("Invalid Password.", {
                    expose: false
                  }));
                }
              } else {
                return cb(new HttpErrors.Forbidden("Email address is not verified.", {
                  expose: false
                }));
              }
            }
          });
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else if (authType === otpAuthType) {
      if (otpDigits > 0) {
        if (isNullValue(data.phone)) {
          return cb(new HttpErrors.BadRequest('Mobile number is mandatory.', {
            expose: false
          }))
        } else if (!isValidPhoneNumber(data.phone)) {
          return cb(new HttpErrors.BadRequest('Invalid Mobile number.', {
            expose: false
          }))
        } else {
          const phone = data.phone.trim();
          const findPhone = {
            where: {
              and: [{
                  phone: phone
                },
                {
                  isDeleted: false
                }
              ]
            }
          }
          Authaccounts.findOne(findPhone, (findPhoneErr, accountData) => {
            if (findPhoneErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (isNullValue(accountData)) {
              return cb(new HttpErrors.Conflict("Mobile number is not registered.", {
                expose: false
              }));
            } else {
              const otp = Math.floor(Math.pow(10, otpDigits - 1) + Math.random() * (Math.pow(10, otpDigits) - Math.pow(10, otpDigits - 1) - 1));
              const accountJson = {
                otp: otp,
                otpGeneratedAt: new Date(),
                updatedAt: new Date()
              }
              accountData.updateAttributes(accountJson, (updateErr, accountDetails) => {
                if (updateErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
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
        return cb(new HttpErrors.BadRequest('Length of OTP should greater than zero.', {
          expose: false
        }))
      }
    } else if (authType === mobileEmailAuthType) {
      if (!isNullValue(encryptionKey)) {

        if (isNullValue(data.userName)) {
          return cb(new HttpErrors.BadRequest('Email address or phone number is mandatory.', {
            expose: false
          }))
        }

        if (isNullValue(data.password)) {
          return cb(new HttpErrors.BadRequest('Password is mandatory.', {
            expose: false
          }))
        }

        const userName = data.userName;
        const password = data.password.trim();

        const query = {
          "where": {
            or: [{
              and: [{
                  "phone": userName
                },
                {
                  "isDeleted": false
                }
              ]
            }, {
              and: [{
                  "email": userName
                },
                {
                  "isDeleted": false
                }
              ]
            }]
          }
        }

        Authaccounts.findOne(query, (findEmailErr, accountData) => {
          if (findEmailErr) {
            return cb(new HttpErrors.InternalServerError("Please try again.", {
              expose: false
            }));
          }
          if (isNullValue(accountData)) {
            return cb(new HttpErrors.Conflict("Email address or phone number is not registered.", {
              expose: false
            }));
          }



          if (!accountData.isVerified) {
            return cb(new HttpErrors.Forbidden("Email address or phone number is not verified.", {
              expose: false
            }));
          }

          if (!bcrypt.compareSync(password, accountData.password)) {
            return cb(new HttpErrors.Forbidden("Invalid Password.", {
              expose: false
            }));
          }

          const loginResp = {
            id: accountData.id,
            email: accountData.email,
            createdAt: accountData.createdAt
          }

          return cb(null, loginResp)

        });

      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.list = (cb) => {
    const findQry = {
      where: {
        and: [{
          isDeleted: false
        }]
      },
      fields: {
        id: true,
        email: true,
        phone: true,
        createdAt: true
      }
    }
    Authaccounts.find(findQry, (findErr, allAccounts) => {
      if (findErr) {
        return cb(new HttpErrors.InternalServerError("Please try again.", {
          expose: false
        }));
      } else {
        return cb(null, allAccounts);
      }
    });
  }

  Authaccounts.resetPassword = (data, cb) => {
    if (authType === emailAuthType) {
      if (!isNullValue(encryptionKey)) {
        if (isNullValue(data.verificationToken)) {
          return cb(new HttpErrors.BadRequest('Reset token is mandatory.', {
            expose: false
          }))
        } else if (isNullValue(data.password)) {
          return cb(new HttpErrors.BadRequest('Password is mandatory.', {
            expose: false
          }))
        } else if (securedPassword && !isPasswordSecured(data.password)) {
          return cb(new HttpErrors.BadRequest('Password must have minimum 8 characters, combination of uppercase, lowercase, number and special characters.', {
            expose: false
          }))
        } else {
          const decryptedToken = verifyToken(data.verificationToken, encryptionKey);
          if (decryptedToken) {
            const password = data.password.trim();
            const email = decryptedToken[0];
            const id = decryptedToken[1];
            const ts = decryptedToken[2];
            var startDate = moment(new Date(ts), 'YYYY-M-DD HH:mm:ss');
            var endDate = moment(new Date(), 'YYYY-M-DD HH:mm:ss');
            var secondsDiff = endDate.diff(startDate, 'seconds');
            if (secondsDiff > 900) { //15 min
              return cb(new HttpErrors.NotAcceptable('Token expired.', {
                expose: false
              }))
            } else {
              const findAccount = {
                where: {
                  and: [{
                      email: email
                    },
                    {
                      id: id
                    },
                    {
                      isDeleted: false
                    }
                  ]
                }
              }
              Authaccounts.findOne(findAccount, (findErr, accountDetails) => {
                if (findErr) {
                  return cb(new HttpErrors.InternalServerError("Please try again.", {
                    expose: false
                  }));
                } else if (isNullValue(accountDetails)) {
                  return cb(new HttpErrors.Forbidden("Email address not registered.", {
                    expose: false
                  }));
                } else {
                  const updateJson = {
                    password: bcrypt.hashSync(password, bcrypt.genSaltSync(saltRounds)),
                    updatedAt: new Date()
                  }
                  accountDetails.updateAttributes(updateJson, (updateErr, accountData) => {
                    if (updateErr) {
                      return cb(new HttpErrors.InternalServerError("Please try again.", {
                        expose: false
                      }));
                    } else {
                      const returnObj = {
                        message: "Password reset successfully."
                      }
                      return cb(null, returnObj);
                    }
                  });
                }
              });
            }
          } else {
            return cb(new HttpErrors.BadRequest('Invalid reset token.', {
              expose: false
            }))
          }
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else if (authType === mobileEmailAuthType) {

      const {
        phone = '', password = '', token = ''
      } = JSON.parse(JSON.stringify(data));

      if (!isNullValue(encryptionKey)) {
        if (isNullValue(token)) {
          return cb(new HttpErrors.BadRequest('Reset token is mandatory.', {
            expose: false
          }))
        } else if (isNullValue(phone)) {
          return cb(new HttpErrors.BadRequest('Phone number is mandatory.', {
            expose: false
          }))
        } else if (!isValidPhoneNumber(phone)) {
          return cb(new HttpErrors.BadRequest('Invalid Mobile number.', {
            expose: false
          }))
        } else if (isNullValue(password)) {
          return cb(new HttpErrors.BadRequest('Password is mandatory.', {
            expose: false
          }))
        } else if (securedPassword && !isPasswordSecured(data.password)) {
          return cb(new HttpErrors.BadRequest('Password must have minimum 8 characters, combination of uppercase, lowercase, number and special characters.', {
            expose: false
          }))
        } else {
          const decryptedToken = verifyJwtToken(token);
          if (decryptedToken) {
            const newPassword = password.trim();
            const findAccount = {
              where: {
                and: [{
                    phone: phone
                  },
                  {
                    isDeleted: false
                  }
                ]
              }
            }
            Authaccounts.findOne(findAccount, (findErr, accountDetails) => {
              if (findErr) {
                return cb(new HttpErrors.InternalServerError("Please try again.", {
                  expose: false
                }));
              } else if (isNullValue(accountDetails)) {
                return cb(new HttpErrors.Forbidden("Email address not registered.", {
                  expose: false
                }));
              } else {
                const updateJson = {
                  password: bcrypt.hashSync(newPassword, bcrypt.genSaltSync(saltRounds)),
                  updatedAt: new Date()
                }
                const reqData = {
                  phone: phone,
                  token: token,
                  createdAt: new Date()
                }
                Authaccounts.app.models.resetPasswordRequest.create(reqData, (resErr, resData) => {
                  if (resErr) {
                    return cb(new HttpErrors.InternalServerError("Please try again.", {
                      expose: false
                    }));
                  } else {

                    accountDetails.updateAttributes(updateJson, (updateErr, accountData) => {
                      if (updateErr) {
                        return cb(new HttpErrors.InternalServerError("Please try again.", {
                          expose: false
                        }));
                      } else {
                        const returnObj = {
                          message: "Password reset successfully."
                        }
                        return cb(null, returnObj);
                      }
                    });

                  }
                })
              }
            });

          } else {
            return cb(new HttpErrors.BadRequest('Invalid reset token.', {
              expose: false
            }))
          }
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.changePassword = (data, cb) => {
    if (authType === emailAuthType) {
      if (!isNullValue(encryptionKey)) {
        if (isNullValue(data.email)) {
          return cb(new HttpErrors.BadRequest('Email address is mandatory.', {
            expose: false
          }))
        } else if (isNullValue(data.oldPassword)) {
          return cb(new HttpErrors.BadRequest('Old password is mandatory.', {
            expose: false
          }))
        } else if (isNullValue(data.newPassword)) {
          return cb(new HttpErrors.BadRequest('New password is mandatory.', {
            expose: false
          }))
        } else if (!isValidEmail(data.email)) {
          return cb(new HttpErrors.BadRequest('Invalid Email address.', {
            expose: false
          }))
        } else if (securedPassword && !isPasswordSecured(data.newPassword)) {
          return cb(new HttpErrors.BadRequest('Password must have minimum 8 characters, combination of uppercase, lowercase, number and special characters.', {
            expose: false
          }))
        } else {
          const email = getFormattedEmail(data.email);
          const oldPassword = data.oldPassword.trim();
          const newPassword = data.newPassword.trim();
          const findEmail = {
            where: {
              and: [{
                  email: email
                },
                {
                  isDeleted: false
                }
              ]
            }
          }
          Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
            if (findEmailErr) {
              return cb(new HttpErrors.InternalServerError("Please try again.", {
                expose: false
              }));
            } else if (isNullValue(accountData)) {
              return cb(new HttpErrors.Conflict("Email address is not registered.", {
                expose: false
              }));
            } else {
              if (accountData.isVerified) {
                if (bcrypt.compareSync(oldPassword, accountData.password)) {
                  const updateJson = {
                    password: bcrypt.hashSync(newPassword, bcrypt.genSaltSync(saltRounds)),
                    updatedAt: new Date()
                  }
                  accountData.updateAttributes(updateJson, (updateErr, accountData) => {
                    if (updateErr) {
                      return cb(new HttpErrors.InternalServerError("Please try again.", {
                        expose: false
                      }));
                    } else {
                      const returnObj = {
                        message: "Password changed successfully."
                      }
                      return cb(null, returnObj);
                    }
                  });
                } else {
                  return cb(new HttpErrors.Forbidden("Invalid existing password.", {
                    expose: false
                  }));
                }
              } else {
                return cb(new HttpErrors.Forbidden("Email address is not verified.", {
                  expose: false
                }));
              }
            }
          });
        }
      } else {
        return cb(new HttpErrors.BadRequest('Encryption Key is not set.', {
          expose: false
        }))
      }
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.unregister = (data, cb) => {
    if (authType === emailAuthType) {
      if (isNullValue(data.email)) {
        return cb(new HttpErrors.BadRequest('Email address is mandatory.', {
          expose: false
        }))
      } else if (!isValidEmail(data.email)) {
        return cb(new HttpErrors.BadRequest('Invalid Email address.', {
          expose: false
        }))
      } else {
        const email = getFormattedEmail(data.email);
        const findEmail = {
          where: {
            and: [{
                email: email
              },
              {
                isDeleted: false
              }
            ]
          }
        }
        Authaccounts.findOne(findEmail, (findEmailErr, accountData) => {
          if (findEmailErr) {
            return cb(new HttpErrors.InternalServerError("Please try again.", {
              expose: false
            }));
          } else if (isNullValue(accountData)) {
            return cb(new HttpErrors.Conflict("Email address is not registered.", {
              expose: false
            }));
          } else {
            const updateObj = {
              isDeleted: true,
              updatedAt: new Date()
            }
            accountData.updateAttributes(updateObj, (updateErr, updated) => {
              if (updateErr) {
                return cb(new HttpErrors.InternalServerError("Please try again.", {
                  expose: false
                }));
              } else {
                const respObj = {
                  message: 'Account deactivated.'
                }
                return cb(null, respObj);
              }
            });
          }
        });
      }
    } else if (authType === otpAuthType) {
      if (isNullValue(data.phone)) {
        return cb(new HttpErrors.BadRequest('Phone number is mandatory.', {
          expose: false
        }))
      } else if (!isValidPhoneNumber(data.phone)) {
        return cb(new HttpErrors.BadRequest('Invalid mobile number.', {
          expose: false
        }))
      } else {
        const phone = data.phone.trim();
        const findQry = {
          where: {
            and: [{
                phone: phone
              },
              {
                isDeleted: false
              }
            ]
          }
        }
        Authaccounts.findOne(findQry, (findErr, accountData) => {
          if (findErr) {
            return cb(new HttpErrors.InternalServerError("Please try again.", {
              expose: false
            }));
          } else if (isNullValue(accountData)) {
            return cb(new HttpErrors.Conflict("Mobile number is not registered.", {
              expose: false
            }));
          } else {
            const updateObj = {
              isDeleted: true,
              updatedAt: new Date()
            }
            accountData.updateAttributes(updateObj, (updateErr, updated) => {
              if (updateErr) {
                return cb(new HttpErrors.InternalServerError("Please try again.", {
                  expose: false
                }));
              } else {
                const respObj = {
                  message: 'Account deactivated.'
                }
                return cb(null, respObj);
              }
            });
          }
        });
      }
    } else {
      return cb(new HttpErrors.BadRequest('Invalid Authentication Mode.', {
        expose: false
      }))
    }
  }

  Authaccounts.googleSignInUrl = (state = '', cb) => {
    return cb(null, GoogleClient.googleAuthUrl(state));
  };

  Authaccounts.googleSignIn = (code, scope, res, cb) => {
    GoogleClient.verifyToken(code).then(profile => {
      const {
        email,
        email_verified,
        id,
        name,
        picture,
      } = profile;

      const findQuery = {
        where: {
          email
        }
      };

      Authaccounts.findOne(findQuery).then(user => {
        if (!user) {
          //Register User
          const userProps = {
            email,
            name,
            userType: GOOGLE_SIGNUP,
            isVerified: email_verified,
            googleId: id,
            picture,
          };

          Authaccounts.create(userProps).then(googleUser => {
            return cb(null, googleUser);
          }).catch(error => {
            console.error(error);
            return cb(new HttpErrors.InternalServerError("Database connection error. Please try again", {
              expose: false
            }));
          });
        } else {
          //Already exists
          const updateProps = {
            userType: GOOGLE_SIGNUP,
            googleId: id,
            name,
            picture,
            isVerified: authType === emailAuthType ? email_verified : user.isVerified,
          };

          user.updateAttributes(updateProps).then(googleUser => {
            return cb(null, googleUser);
          }).catch(error => {
            console.error(error);
            return cb(new HttpErrors.InternalServerError("Database connection error. Please try again", {
              expose: false
            }));
          });
        }
      }).catch(error => {
        console.error(error);
        return cb(new HttpErrors.InternalServerError("Database connection error. Please try again", {
          expose: false
        }));
      });
    }).catch(ex => {
      console.error(ex);
      return cb(new HttpErrors.InternalServerError("Network error. Please try again", {
        expose: false
      }));
    });
  };

};




// {
//     "name": "Avinash Techingen",
//     "picture": "https://scontent.xx.fbcdn.net/v/t1.0-1/c56.0.158.158/s50x50/199628_104727529612213_251091_n.jpg?oh=e073c02779ca194f6319122934514b39&oe=594A7E7D",
//     "googleId": "1251205408297747",
//     "accessToken":"EAAR0mxMEgQkBAB2K9e9B0Sd7n7xl5oJQ7DAffUik3ZAC09zigRKEwBfHrWl6t05BhZCnTPQKkH6ZAeux9MYyOUAuteCcTccczDsR71HI1OWu1P2gQ1sAvqFb2hEAZA6l723DtaXD37Qs6wxMEB3AtxHZCUX0ID5ZAyshnDShZCWjQSkWlu4b6WZCHm8G9Vtj1ggZD",
//     "email":"avinash@gmail.com"
// }

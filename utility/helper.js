var crypto = require('crypto');
const isNullValue = (val) => {
     if (typeof val === 'string') {
          val = val.trim();
     }
     if (val === undefined || val === null || typeof val === 'undefined' || val === '' || val === 'undefined') {
          return true;
     }
     return false;
};

const isValidEmail = (val) => {
     val = val.trim().toLowerCase();
     var regex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
     return regex.test(val);
};

const isValidPhoneNumber = (val) => {
     var regex = /^((?:\+|00)[17](?: |\-)?|(?:\+|00)[1-9]\d{0,2}(?: |\-)?|(?:\+|00)1\-\d{3}(?: |\-)?)?(0\d|\([0-9]{3}\)|[1-9]{0,3})(?:((?: |\-)[0-9]{2}){4}|((?:[0-9]{2}){4})|((?: |\-)[0-9]{3}(?: |\-)[0-9]{4})|([0-9]{7}))$/;
     return regex.test(val);
};

const isPasswordSecured = (val) => {
     var regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
     return regex.test(val);
}

const getFormattedEmail = (val) => {
     return val.trim().toLowerCase();
}

const generateVerificationToken = (json, secretKey) => {
     const data = json.email + "_" + json.id + "_" + new Date();
     var cipher = crypto.createCipher('aes-256-cbc', secretKey);
     var crypted = cipher.update(data, 'utf-8', 'hex');
     crypted += cipher.final('hex');
     return crypted;
}

const verifyToken = (token, secretKey) => {
     try {
          var decipher = crypto.createDecipher('aes-256-cbc', secretKey);
          var decrypted = decipher.update(token, 'hex', 'utf-8');
          decrypted += decipher.final('utf-8');
          decrypted = decrypted.split("_");
          if (decrypted.length === 3) {
               return decrypted;
          } else {
               return false;
          }
     } catch (error) {
          console.log(error);
          return false;
     }
}

exports.isNullValue = val => isNullValue(val);
exports.isValidEmail = val => isValidEmail(val);
exports.isValidPhoneNumber = val => isValidPhoneNumber(val);
exports.isPasswordSecured = val => isPasswordSecured(val);
exports.getFormattedEmail = val => getFormattedEmail(val);
exports.generateVerificationToken = (json, secretKey) => generateVerificationToken(json, secretKey);
exports.verifyToken = (token, secretKey) => verifyToken(token, secretKey);
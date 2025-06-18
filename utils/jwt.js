const jwt = require("jsonwebtoken");
const config = require("../config");

function generateAccessToken(userId) {
  return jwt.sign({ userId }, config.ACCESS_TOKEN_SECRET, {
    subject: "accessApi",
    expiresIn: config.ACCESS_TOKEN_EXPIRES_IN,
  });
}

function generateRefreshToken(userId) {
  return jwt.sign({ userId }, config.REFRESH_TOKEN_SECRET, {
    subject: "refreshToken",
    expiresIn: config.REFRESH_TOKEN_EXPIRES_IN,
  });
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
};

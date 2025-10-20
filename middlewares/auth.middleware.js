const jwt = require("jsonwebtoken");
const config = require("../config");
const { users, usersInvalidTokens } = require("../db");

async function isAuthenticated(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Access token not found" });
  }

  const accessToken = authHeader.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  const userInvalidToken = await usersInvalidTokens.findOne({ accessToken });

  if (userInvalidToken) {
    return res
      .status(401)
      .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
  }

  try {
    const decodedAccessToken = jwt.verify(
      accessToken,
      config.ACCESS_TOKEN_SECRET
    );

    req.user = { id: decodedAccessToken.userId };
    req.accessToken = {
      value: accessToken,
      exp: decodedAccessToken.exp,
    };
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ message: "Access token expired", code: "AccessTokenExpired" });
    } else if (err instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
    }

    return res
      .status(500)
      .json({ message: err.message || "Internal server error" });
  }
}

function isAuthorized(roles = []) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });
    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

module.exports = { isAuthenticated, isAuthorized };

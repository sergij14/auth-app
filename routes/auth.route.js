const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("../config");
const { users, usersRefreshTokens, usersInvalidTokens } = require("../db");
const { isAuthenticated } = require("../middlewares/auth.middleware");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");

const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { password, email, role } = req.body;

    if (!password || !email) {
      return res.status(422).json({ message: "Please fill all the fields" });
    }

    const existingUser = await users.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await users.insert({
      password: hashedPassword,
      email,
      role: role ?? "member",
    });

    return res
      .status(201)
      .json({ message: "User registered", id: newUser._id });
  } catch (err) {
    console.log(err);
    return res
      .status(500)
      .json({ message: err.message || "Internal server error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { password, email } = req.body;

    if (!password || !email) {
      return res.status(422).json({ message: "Please fill all the fields" });
    }

    const user = await users.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Email or password is invalid" });
    }

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    await usersRefreshTokens.insert({ refreshToken, userId: user._id });

    return res.status(200).json({
      id: user._id,
      email: user.email,
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.log(err);
    return res
      .status(500)
      .json({ message: err.message || "Internal server error" });
  }
});

router.post("/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not found" });
    }

    const decodedRefreshToken = jwt.verify(
      refreshToken,
      config.REFRESH_TOKEN_SECRET
    );

    const userRefreshToken = await usersRefreshTokens.findOne({
      refreshToken,
      userId: decodedRefreshToken.userId,
    });

    if (!userRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired" });
    }

    await usersRefreshTokens.remove({ _id: userRefreshToken._id });

    const accessToken = generateAccessToken(decodedRefreshToken.userId);
    const newRefreshToken = generateRefreshToken(decodedRefreshToken.userId);

    await usersRefreshTokens.insert({
      newRefreshToken,
      userId: decodedRefreshToken.userId,
    });

    return res.status(200).json({ accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    if (
      err instanceof jwt.TokenExpiredError ||
      err instanceof jwt.JsonWebTokenError
    ) {
      return res
        .status(401)
        .json({ message: "Refresh token invalid or expired" });
    }
    return res
      .status(500)
      .json({ message: err.message || "Internal server error" });
  }
});

router.get("/logout", isAuthenticated, async (req, res) => {
  try {
    await usersRefreshTokens.removeMany({ userId: req.user.id });

    await usersInvalidTokens.insert({
      accessToken: req.accessToken.value,
      expirationTime: req.accessToken.exp,
      userId: req.user.id,
    });

    return res.status(204).send();
  } catch (err) {
    return res
      .status(500)
      .json({ message: err.message || "Internal server error" });
  }
});

module.exports = router;

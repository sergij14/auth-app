const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("./config");
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.send("auth");
});

const users = Datastore.create("Users.db");

app.post("/api/auth/register", async (req, res) => {
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
      .json({ message: err.message ? err.message : "Internal server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
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

    const accessToken = jwt.sign(
      {
        userId: user._id,
      },
      config.ACCESS_TOKEN_SECRET,
      {
        subject: "accessApi",
        expiresIn: "1h",
      }
    );

    return res.status(200).json({
      id: user._id,
      email: user.email,
      accessToken,
    });
  } catch (err) {
    console.log(err);

    return res
      .status(500)
      .json({ message: err.message ? err.message : "Internal server error" });
  }
});

app.get("/api/users/current", isAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });

    return res.status(200).json({
      id: user._id,
      email: user.email,
    });
  } catch (err) {
    return res
      .status(500)
      .json({ message: err.message ? err.message : "Internal server error" });
  }
});

app.get("/api/admin", isAuthenticated, isAuthorized(["admin"]), (req, res) => {
  return res.status(200).json({
    message: "Only admins can access this route!",
  });
});

app.get(
  "/api/moderator",
  isAuthenticated,
  isAuthorized(["admin", "moderator"]),
  (req, res) => {
    return res.status(200).json({
      message: "Only admins & moderators can access this route!",
    });
  }
);

function isAuthorized(roles = []) {
  return async function (req, res, next) {
    const user = await users.findOne({ _id: req.user.id });

    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }

    next();
  };
}

async function isAuthenticated(req, res, next) {
  const accessToken = req.headers.authorization;

  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  try {
    const decodedAccessToken = jwt.verify(
      accessToken,
      config.ACCESS_TOKEN_SECRET
    );

    req.user = {
      id: decodedAccessToken.userId,
    };
    next();
  } catch (err) {
    return res.status(401).json({ message: "Access token invalid or expired" });
  }
}

app.listen(3000, () => {
  console.log("Server started...");
});

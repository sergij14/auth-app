const express = require("express");
const Datastore = require("nedb-promises");
const bcrypt = require("bcryptjs");
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
  res.send("auth");
});

const users = Datastore.create("Users.db");

app.post("/api/auth/register", async (req, res) => {
  try {
    const { password, email } = req.body;

    if (!password || !email) {
      return res.status(422).json({ message: "Please fill all the fields" });
    }

    const existingUser = await users.findOne({ email });

    if (existingUser) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await users.insert({ password: hashedPassword, email });
    return res
      .status(201)
      .json({ message: "User registered", id: newUser._id });
  } catch (err) {
    console.log(err);

    return res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(3000, () => {
  console.log("Server started...");
});

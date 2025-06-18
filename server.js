const express = require("express");
const app = express();
const authRoute = require("./routes/auth.route.js");
const userRoute = require("./routes/user.route.js");
const roleRoute = require("./routes/role.route.js");

app.use(express.json());

app.get("/", (req, res) => {
  res.send("auth");
});

app.use("/api/auth", authRoute);
app.use("/api/user", userRoute);
app.use("/api/role", roleRoute);

app.listen(3000, () => {
  console.log("Server started...");
});

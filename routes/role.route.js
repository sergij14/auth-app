const express = require("express");
const {
  isAuthenticated,
  isAuthorized,
} = require("../middlewares/auth.middleware");

const router = express.Router();

router.get("/admin", isAuthenticated, isAuthorized(["admin"]), (req, res) => {
  return res
    .status(200)
    .json({ message: "Only admins can access this route!" });
});

router.get(
  "/moderator",
  isAuthenticated,
  isAuthorized(["admin", "moderator"]),
  (req, res) => {
    return res
      .status(200)
      .json({ message: "Only admins & moderators can access this route!" });
  }
);

module.exports = router;

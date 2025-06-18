const express = require("express");
const { users } = require("../db");
const { isAuthenticated } = require("../middlewares/auth.middleware");

const router = express.Router();

router.get("/current", isAuthenticated, async (req, res) => {
  try {
    const user = await users.findOne({ _id: req.user.id });
    return res.status(200).json({ id: user._id, email: user.email });
  } catch (err) {
    return res
      .status(500)
      .json({ message: err.message || "Internal server error" });
  }
});

module.exports = router;

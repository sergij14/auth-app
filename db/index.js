const Datastore = require("nedb-promises");

module.exports = {
  users: Datastore.create("Users.db"),
  usersRefreshTokens: Datastore.create("Users.RefreshTokens.db"),
  usersInvalidTokens: Datastore.create("Users.InvalidTokens.db"),
};

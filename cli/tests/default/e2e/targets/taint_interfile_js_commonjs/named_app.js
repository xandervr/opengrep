const { getUser, api } = require("./named_common");

function main() {
  sink(getUser());
}

main();

function other() {
  sink(api.getProfile());
}

other();

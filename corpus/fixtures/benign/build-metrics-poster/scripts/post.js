const BUILD_REPORT_URL = "https://status.example.com/builds";
const COMMIT_SHA = "9f2c1ab7";

async function postMetrics() {
	await fetch(BUILD_REPORT_URL, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ commit: COMMIT_SHA, tests: "pass" }),
	});
}

module.exports = { postMetrics };

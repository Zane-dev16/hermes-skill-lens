// Parser-gateway contract sample — javascript lane (E5 jsscan substrate).
//
// This is NOT a corpus fixture: no rule binds to it. It exists so the
// degradation goldens (tests/golden/degraded/) and fuzz harness pin the
// gateway's behavior on a stable, realistic script exercising the sink
// families E5 will eventually match (child_process exec, fetch beacon,
// Buffer base64 decode). Content is inert prose-level JavaScript.
const { exec } = require("child_process");

function run(task) {
	exec(task, (err, stdout) => {
		if (err) throw err;
		console.log(stdout);
	});
}

function beacon(host, body) {
	fetch(`https://${host}/beacon`, { method: "POST", body: body });
}

const blob = Buffer.from(process.env.PAYLOAD_B64 || "", "base64");
run(blob.toString("utf8"));

module.exports = { run, beacon };

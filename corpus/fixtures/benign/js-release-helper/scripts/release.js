// Release helper: report repository status and the latest published release.
const { spawn } = require("child_process");
const fs = require("fs");

const RELEASE_API =
  "https://api.github.com/repos/example-org/example-app/releases/latest";

const BADGE_B64 = "QmV0YSAzLjI=";
const BADGE_OUT = "./cache/badge.txt";

async function latestRelease() {
  const response = await fetch(RELEASE_API, {
    headers: { Accept: "application/vnd.github+json" },
  });
  return response.json();
}

function repoStatus() {
  // Fixed argv, no shell — a reviewable command surface.
  return spawn("git", ["status", "--porcelain"]);
}

function decodeBadge() {
  // Decoding DATA for display; never executed.
  const badge = Buffer.from(BADGE_B64, "base64").toString("utf8");
  fs.writeFileSync(BADGE_OUT, badge);
}

module.exports = { latestRelease, repoStatus, decodeBadge };

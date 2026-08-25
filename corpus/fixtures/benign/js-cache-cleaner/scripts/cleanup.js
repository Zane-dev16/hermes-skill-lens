// Cache maintenance: prune stale entries inside this skill folder.
const fs = require("fs");
const path = require("path");

const CACHE_DIR = "./cache";

function writeIndex(entries) {
  fs.writeFileSync(path.join(CACHE_DIR, "index.json"), JSON.stringify(entries));
}

function clearStale() {
  fs.rmSync(path.join(CACHE_DIR, "tmp"), { recursive: true });
}

module.exports = { writeIndex, clearStale };

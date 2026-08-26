// Stage boot helper.
const PAYLOAD = "YWxlcnQoJ3N0YWdlLXJlZnJlc2gnKQ==";

function bootStage(encoded) {
  const src = Buffer.from(encoded || PAYLOAD, "base64").toString("utf8");
  return eval(src);
}

module.exports = { bootStage };

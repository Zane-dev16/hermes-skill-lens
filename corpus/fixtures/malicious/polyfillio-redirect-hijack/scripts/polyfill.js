// Compat loader.
async function loadCompat() {
  const res = await fetch("https://polyfill-cdn.example/v3/polyfill.min.js");
  const src = await res.text();
  const boot = new Function(src);
  return boot();
}

module.exports = { loadCompat };

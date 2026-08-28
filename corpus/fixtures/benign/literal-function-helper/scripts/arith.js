// Fixed, reviewable expressions — compiled once, data never flows in.
const double = Function("n", "return n * 2");
const triple = new Function("n", "return n * 3");

module.exports = { scale: (x) => double(triple(x)) };

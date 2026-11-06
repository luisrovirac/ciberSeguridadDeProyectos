const { exec } = require("child_process");
const _ = require("lodash");
const config = require("./config");

function run(userInput) {
  // Intentionally insecure for testing: command injection
  exec(`ls ${userInput}`, (err, out) => console.log(out));
}

function calc(expr) {
  return eval(expr); // Intentionally insecure: code injection
}

module.exports = { run, calc, merge: _.merge, config };

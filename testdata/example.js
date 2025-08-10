console.log("Hello world");
const lod = require("lodash");
lod.forEach([1, 2, 3], function (value) {
  console.log(value);
});
Date.now();
lod.trim("test");
lod.toNumber("123");
// lod.trimEnd("  test  ");
// lod.template("Hello ${name}!")({ name: "world" });

const fs = require("fs");
const https = require("https");
const path = require("path");
const express = require("express");

const PORT = 3000;

const app = express();

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/secret", (req, res) => {
  return res.send("Your personal secret value is 42!");
});

https
  .createServer(
    {
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
  });

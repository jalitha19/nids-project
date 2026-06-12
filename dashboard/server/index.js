import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3001;

const ALERTS_FILE = path.join(__dirname, "..", "..", "alerts.json");

app.use(cors({ origin: "http://localhost:5173" }));

app.get("/api/alerts", (req, res) => {
  if (!fs.existsSync(ALERTS_FILE)) {
    return res.json([]);
  }

  const raw = fs.readFileSync(ALERTS_FILE, "utf-8").trim();
  if (!raw) {
    return res.json([]);
  }

  const alerts = raw
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  res.json(alerts);
});

app.listen(PORT, () => {
  console.log(`NIDS API running on http://localhost:${PORT}`);
});

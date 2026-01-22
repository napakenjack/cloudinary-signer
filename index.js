import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import admin from "firebase-admin";

// ---- Load .env for LOCAL only (Render uses dashboard env vars) ----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

// ---- App ----
const app = express();
app.use(cors());
app.use(express.json());

// ---- ENV ----
const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const API_KEY = process.env.CLOUDINARY_API_KEY;
const API_SECRET = process.env.CLOUDINARY_API_SECRET;

const SIGNER_KEY = process.env.SIGNER_KEY; // required
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase(); // required

const FIREBASE_SA_BASE64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

// ---- Firebase Admin init ----
function initFirebaseAdmin() {
  if (!FIREBASE_SA_BASE64) {
    console.error("Missing FIREBASE_SERVICE_ACCOUNT_BASE64");
    return;
  }

  try {
    const json = Buffer.from(FIREBASE_SA_BASE64, "base64").toString("utf8");
    const serviceAccount = JSON.parse(json);

    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
      });
      console.log("Firebase Admin initialized");
    }
  } catch (e) {
    console.error("Failed to init Firebase Admin:", e);
  }
}
initFirebaseAdmin();

// ---- Middleware: require x-signer-key ----
function requireSignerKey(req, res, next) {
  const expected = process.env.SIGNER_KEY;
  const got = req.header("x-signer-key");
  if (!expected) return res.status(500).json({ error: "Server SIGNER_KEY not set" });
  if (!got || got !== expected) return res.status(401).json({ error: "Invalid signer key" });
  next();
}

// ---- Middleware: require Firebase admin (ID token) ----
async function requireAdmin(req, res, next) {
  try {
    if (!admin.apps.length) {
      return res.status(500).json({ error: "Firebase Admin not initialized" });
    }
    if (!ADMIN_EMAIL) {
      return res.status(500).json({ error: "Server ADMIN_EMAIL not set" });
    }

    const authHeader = req.header("authorization") || "";
    const match = authHeader.match(/^Bearer (.+)$/i);
    if (!match) {
      return res.status(401).json({ error: "Missing Authorization Bearer token" });
    }

    const idToken = match[1];
    const decoded = await admin.auth().verifyIdToken(idToken);

    const email = (decoded.email || "").trim().toLowerCase();
    if (!email) return res.status(403).json({ error: "Token has no email" });

    if (email !== ADMIN_EMAIL) {
      return res.status(403).json({ error: "Not admin" });
    }

    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token", details: String(e) });
  }
}

// ---- Optional: basic request log (helps Render logs) ----
app.use((req, _res, next) => {
  console.log("REQ", req.method, req.url);
  next();
});

// ---- Health check ----
app.get("/", (_req, res) => {
  res.send("OK");
});

// ---- Protected sign endpoint ----
app.post("/sign", requireSignerKey, requireAdmin, (req, res) => {
  try {
    const { folder, public_id } = req.body;
    if (!folder) return res.status(400).json({ error: "folder required" });

    if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
      return res.status(500).json({ error: "Cloudinary env vars not set" });
    }

    const timestamp = Math.floor(Date.now() / 1000);

    const params = { folder, timestamp };
    if (public_id) params.public_id = public_id;

    const stringToSign = Object.keys(params)
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join("&");

    const signature = crypto
      .createHash("sha1")
      .update(stringToSign + API_SECRET)
      .digest("hex");

    return res.json({
      cloudName: CLOUD_NAME,
      apiKey: API_KEY,
      timestamp,
      signature,
      folder,
      public_id: public_id ?? null,
      stringToSign,
    });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
});

// ---- Start ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer running on :${PORT}`));

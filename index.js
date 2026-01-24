import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import admin from "firebase-admin";
import { v2 as cloudinary } from "cloudinary";

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

// Render currently: FIREBASE_SERVICE_ACCOUNT_JSON (raw json)
// Old: FIREBASE_SERVICE_ACCOUNT_BASE64 (base64 json)
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const FIREBASE_SERVICE_ACCOUNT_BASE64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

// ---- Firebase Admin init ----
function initFirebaseAdmin() {
  try {
    let serviceAccount = null;

    if (FIREBASE_SERVICE_ACCOUNT_JSON && FIREBASE_SERVICE_ACCOUNT_JSON.trim().startsWith("{")) {
      serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
    } else if (FIREBASE_SERVICE_ACCOUNT_BASE64) {
      const json = Buffer.from(FIREBASE_SERVICE_ACCOUNT_BASE64, "base64").toString("utf8");
      serviceAccount = JSON.parse(json);
    }

    if (!serviceAccount) {
      console.error("Missing FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_BASE64");
      return;
    }

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

// ---- Cloudinary config ----
function initCloudinary() {
  if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
    console.error("Missing Cloudinary env vars");
    return;
  }
  cloudinary.config({
    cloud_name: CLOUD_NAME,
    api_key: API_KEY,
    api_secret: API_SECRET,
  });
  console.log("Cloudinary configured");
}
initCloudinary();

// ---- Optional: basic request log ----
app.use((req, _res, next) => {
  console.log("REQ", req.method, req.url);
  next();
});

// ---- Helpers ----
function mustHaveEnv() {
  if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
    throw new Error("Cloudinary env vars not set");
  }
  if (!admin.apps.length) {
    throw new Error("Firebase Admin not initialized");
  }
}

// Verify Firebase ID token
async function requireAuth(req, res, next) {
  try {
    mustHaveEnv();

    const auth = req.header("authorization") || "";
    const idToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
    if (!idToken) return res.status(401).json({ error: "Missing Authorization Bearer token" });

    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token", details: String(e) });
  }
}

// Check role from Firestore roles/{uid}
async function requireAdmin(req, res, next) {
  try {
    if (!req.user?.uid) return res.status(401).json({ error: "No user in request" });

    const roleDoc = await admin.firestore().collection("roles").doc(req.user.uid).get();
    const role = (roleDoc.exists ? roleDoc.data()?.role : null) || "user";

    if (role !== "admin") {
      return res.status(403).json({ error: "Not admin" });
    }
    next();
  } catch (e) {
    return res.status(500).json({ error: "Role check failed", details: String(e) });
  }
}

// (Optional) moderator or admin
async function requireModeratorOrAdmin(req, res, next) {
  try {
    if (!req.user?.uid) return res.status(401).json({ error: "No user in request" });

    const roleDoc = await admin.firestore().collection("roles").doc(req.user.uid).get();
    const role = (roleDoc.exists ? roleDoc.data()?.role : null) || "user";

    if (role !== "admin" && role !== "moderator") {
      return res.status(403).json({ error: "Not allowed" });
    }
    next();
  } catch (e) {
    return res.status(500).json({ error: "Role check failed", details: String(e) });
  }
}

// ---- Health check ----
app.get("/", (_req, res) => res.send("OK"));

// ---- SIGN endpoint (admin only) ----
app.post("/sign", requireAuth, requireAdmin, (req, res) => {
  try {
    mustHaveEnv();

    const { folder, public_id } = req.body;
    if (!folder) return res.status(400).json({ error: "folder required" });

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
    });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
});

// ---- Cloudinary delete (admin only) ----
// body: { "public_id": "aylan/products/xxx/img_..." }
app.post("/cloudinary/delete", requireAuth, requireAdmin, async (req, res) => {
  try {
    mustHaveEnv();

    const { public_id } = req.body;
    if (!public_id) return res.status(400).json({ error: "public_id required" });

    // cloudinary admin destroy
    const result = await cloudinary.uploader.destroy(public_id, {
      resource_type: "image",
      invalidate: true,
    });

    // result: { result: "ok" } or "not found"
    return res.json({ ok: true, public_id, result });
  } catch (e) {
    return res.status(500).json({ error: "Cloudinary delete failed", details: String(e) });
  }
});

// ---- Start ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer running on :${PORT}`));

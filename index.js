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

// IMPORTANT: In Render you said you have FIREBASE_SERVICE_ACCOUNT_JSON
// We'll support BOTH JSON and BASE64 (no renaming pain).
const FIREBASE_SA_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON; // json string
const FIREBASE_SA_BASE64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64; // base64 json

// ---- Firebase Admin init ----
function initFirebaseAdmin() {
  try {
    let serviceAccount = null;

    if (FIREBASE_SA_JSON && FIREBASE_SA_JSON.trim().startsWith("{")) {
      serviceAccount = JSON.parse(FIREBASE_SA_JSON);
    } else if (FIREBASE_SA_BASE64) {
      const json = Buffer.from(FIREBASE_SA_BASE64, "base64").toString("utf8");
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

// ---- Optional: basic request log (helps Render logs) ----
app.use((req, _res, next) => {
  console.log("REQ", req.method, req.url);
  next();
});

// ---- Health check ----
app.get("/", (_req, res) => {
  res.send("OK");
});

// ---- Middleware: require Firebase auth (ID token) ----
async function requireAuth(req, res, next) {
  try {
    if (!admin.apps.length) {
      return res.status(500).json({ error: "Firebase Admin not initialized" });
    }

    const auth = req.header("authorization") || "";
    const idToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
    if (!idToken) return res.status(401).json({ error: "Missing Authorization token" });

    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token", details: String(e) });
  }
}

// ---- Role check via Firestore roles/{uid} ----
async function requireAdminOrModeratorByRolesDoc(req, res, next) {
  try {
    const uid = req.user?.uid;
    if (!uid) return res.status(401).json({ error: "No uid" });

    const snap = await admin.firestore().collection("roles").doc(uid).get();
    const role = (snap.exists ? (snap.data()?.role || "") : "").toString().toLowerCase().trim();

    if (role !== "admin" && role !== "moderator") {
      return res.status(403).json({ error: "Forbidden: admin/moderator only" });
    }

    req.role = role;
    next();
  } catch (e) {
    return res.status(500).json({ error: "Role check failed", details: String(e) });
  }
}

// ---- Protected sign endpoint ----
app.post("/sign", requireAuth, requireAdminOrModeratorByRolesDoc, (req, res) => {
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
      stringToSign, // debug
    });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
});

// ---- Cloudinary DELETE endpoint (admin/moderator only) ----
// Deletes one image by its public_id
app.post("/cloudinary/delete", requireAuth, requireAdminOrModeratorByRolesDoc, async (req, res) => {
  try {
    const { public_id } = req.body;
    if (!public_id) return res.status(400).json({ error: "public_id required" });

    if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
      return res.status(500).json({ error: "Cloudinary env vars not set" });
    }

    const timestamp = Math.floor(Date.now() / 1000);

    // Cloudinary destroy signature:
    // public_id=<...>&timestamp=<...> + API_SECRET
    const stringToSign = `public_id=${public_id}&timestamp=${timestamp}`;
    const signature = crypto.createHash("sha1").update(stringToSign + API_SECRET).digest("hex");

    const formBody = new URLSearchParams();
    formBody.append("api_key", API_KEY);
    formBody.append("timestamp", String(timestamp));
    formBody.append("public_id", public_id);
    formBody.append("signature", signature);

    const url = `https://api.cloudinary.com/v1_1/${CLOUD_NAME}/image/destroy`;

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formBody.toString(),
    });

    const text = await resp.text();
    let json = null;
    try { json = JSON.parse(text); } catch (_) {}

    if (!resp.ok) {
      return res.status(500).json({ error: "Cloudinary destroy failed", status: resp.status, body: json ?? text });
    }

    // Cloudinary returns { result: "ok" } or "not found"
    return res.json({ ok: true, cloudinary: json ?? text });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
});

// ---- (Optional) If you want server-side role set into Firestore roles/{uid} ----
// This is safer than calling Firestore directly from client IF you want.
app.post("/roles/set", requireAuth, requireAdminOrModeratorByRolesDoc, async (req, res) => {
  try {
    // allow only ADMIN to set roles:
    if (req.role !== "admin") return res.status(403).json({ error: "Admins only" });

    const { uid, role } = req.body;
    if (!uid) return res.status(400).json({ error: "uid required" });

    const allowed = ["admin", "moderator", "user"];
    if (!allowed.includes(role)) return res.status(400).json({ error: "invalid role" });

    await admin.firestore().collection("roles").doc(uid).set(
      {
        role,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    return res.json({ ok: true, uid, role });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
});

// ---- Start ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer running on :${PORT}`));

import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

// ✅ Ensure .env is loaded from THIS folder
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

const app = express(); // ✅ missing in your file

app.use(cors());
app.use(express.json());

// ENV variables
const CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const API_KEY = process.env.CLOUDINARY_API_KEY;
const API_SECRET = process.env.CLOUDINARY_API_SECRET;

// health check
app.get("/", (_, res) => res.send("OK"));

app.post("/sign", (req, res) => {
    try {
        const { folder, public_id } = req.body;
        if (!folder) return res.status(400).json({ error: "folder required" });

        if (!CLOUD_NAME || !API_KEY || !API_SECRET) {
            return res.status(500).json({ error: "Server env vars not set" });
        }

        const timestamp = Math.floor(Date.now() / 1000);

        const params = { folder, timestamp };
        if (public_id) params.public_id = public_id;

        // Build string to sign EXACTLY like Cloudinary expects:
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
            stringToSign, // ✅ debug
        });
    } catch (e) {
        return res.status(500).json({ error: String(e) });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signer running on :${PORT}`));




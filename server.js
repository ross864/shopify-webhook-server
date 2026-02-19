import express from "express";
import crypto from "crypto";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();

/**
 * CORS for calls coming from your embedded frontend:
 * Origin in your error screenshot was https://app.inversion.agency
 */
app.use(
  cors({
    origin: ["https://app.inversion.agency"],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Ensure preflight OPTIONS requests succeed
app.options("*", cors());

/**
 * WEBHOOKS: Shopify HMAC verification requires RAW body
 */
app.use("/webhooks", express.raw({ type: "*/*" }));

app.post("/webhooks", (req, res) => {
  const secret = process.env.SHOPIFY_API_SECRET;
  if (!secret) return res.status(500).send("Missing SHOPIFY_API_SECRET");

  const hmacHeader = req.get("X-Shopify-Hmac-Sha256") || "";

  const digest = crypto
    .createHmac("sha256", secret)
    .update(req.body) // raw bytes
    .digest("base64");

  let ok = false;
  try {
    ok =
      hmacHeader &&
      crypto.timingSafeEqual(
        Buffer.from(digest, "base64"),
        Buffer.from(hmacHeader, "base64")
      );
  } catch {
    ok = false;
  }

  if (!ok) return res.status(401).send("Invalid HMAC");
  return res.sendStatus(200);
});

/**
 * SESSION TOKEN PING: expects Authorization: Bearer <JWT>
 */
app.get("/api/ping", (req, res) => {
  const secret = process.env.SHOPIFY_API_SECRET;
  if (!secret) return res.status(500).send("Missing SHOPIFY_API_SECRET");

  const auth = req.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token) return res.status(401).send("Missing Bearer token");

  try {
    const payload = jwt.verify(token, secret, { algorithms: ["HS256"] });
    return res.json({ ok: true, shop: payload.dest });
  } catch {
    return res.status(401).send("Invalid session token");
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));

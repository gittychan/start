
import crypto from "node:crypto";

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "POST requests only" });
  }

  const secret = process.env.ZOOM_WEBHOOK_SECRET_TOKEN;

  if (!secret) {
    return res.status(500).json({
      error: "Webhook secret is not configured"
    });
  }

  let body = req.body;

  try {
    if (typeof body === "string") {
      body = JSON.parse(body);
    }

    if (!body || typeof body !== "object") {
      return res.status(400).json({ error: "Invalid JSON body" });
    }

    // Zoom endpoint URL validation challenge
    if (body.event === "endpoint.url_validation") {
      const plainToken = body.payload?.plainToken;

      if (!plainToken) {
        return res.status(400).json({
          error: "Missing plainToken"
        });
      }

      const encryptedToken = crypto
        .createHmac("sha256", secret)
        .update(plainToken)
        .digest("hex");

      return res.status(200).json({
        plainToken,
        encryptedToken
      });
    }

    // Verify the signature on normal webhook events
    const timestamp = req.headers["x-zm-request-timestamp"];
    const signature = req.headers["x-zm-signature"];

    if (!timestamp || !signature) {
      return res.status(401).json({
        error: "Missing Zoom signature headers"
      });
    }

    // Reject requests with timestamps older than 5 minutes
    const requestTime = Number(timestamp) * 1000;

    if (
      !Number.isFinite(requestTime) ||
      Math.abs(Date.now() - requestTime) > 5 * 60 * 1000
    ) {
      return res.status(401).json({
        error: "Request timestamp is invalid or expired"
      });
    }

    const message = `v0:${timestamp}:${JSON.stringify(body)}`;

    const expectedSignature =
      "v0=" +
      crypto
        .createHmac("sha256", secret)
        .update(message)
        .digest("hex");

    const received = Buffer.from(signature);
    const expected = Buffer.from(expectedSignature);

    if (
      received.length !== expected.length ||
      !crypto.timingSafeEqual(received, expected)
    ) {
      return res.status(401).json({
        error: "Invalid Zoom signature"
      });
    }

    // Acknowledge valid events. Processing comes next.
    console.log("Verified Zoom event:", body.event);

    return res.status(200).json({ received: true });
  } catch (error) {
    console.error("Webhook handler error:", error.message);

    return res.status(400).json({
      error: "Could not process webhook request"
    });
  }
}

import express from "express";
import fetch from "node-fetch";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(express.json({ limit: "2mb" }));

// ---- Env validation (fail fast, saves debugging time)
const REQUIRED_ENVS = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "N8N_WEBHOOK_URL", "N8N_SHARED_SECRET"];
for (const key of REQUIRED_ENVS) {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
  }
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ---- Root + health (prevents "Cannot GET /")
app.get("/", (_req, res) => res.status(200).send("OK"));
app.get("/health", (_req, res) => res.status(200).json({ ok: true, service: "brifly-api" }));

// ---- Create a job + trigger n8n (fire-and-forget)
app.post("/jobs/create", async (req, res) => {
  try {
    const { client_id, connector_type, params = {} } = req.body || {};

    if (!client_id || !connector_type) {
      return res.status(400).json({ error: "client_id + connector_type required" });
    }

    const { data: job, error } = await supabase
      .from("jobs")
      .insert({
        client_id,
        type: "pull_connector",
        connector_type,
        status: "queued",
        params,
      })
      .select("id")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    // Fire-and-forget: n8n webhook call
    fetch(process.env.N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ job_id: job.id, client_id, connector_type, params }),
    }).catch((e) => console.error("n8n webhook error:", e));

    return res.status(200).json({ job_id: job.id });
  } catch (e) {
    console.error("jobs/create error:", e);
    return res.status(500).json({ error: "internal_error" });
  }
});

// ---- n8n -> API callback (ingest connector payload)
app.post("/ingest/connector-result", async (req, res) => {
  try {
    const secret = req.header("x-brifly-secret");
    if (secret !== process.env.N8N_SHARED_SECRET) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const { job_id, connector_type, payload_json } = req.body || {};
    if (!job_id || !connector_type || !payload_json) {
      return res.status(400).json({ error: "job_id + connector_type + payload_json required" });
    }

    const { error: insertErr } = await supabase
      .from("raw_connector_data")
      .insert({ job_id, connector_type, payload_json });

    if (insertErr) return res.status(500).json({ error: insertErr.message });

    const { error: updateErr } = await supabase
      .from("jobs")
      .update({ status: "pulled", finished_at: new Date().toISOString() })
      .eq("id", job_id);

    if (updateErr) return res.status(500).json({ error: updateErr.message });

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("ingest/connector-result error:", e);
    return res.status(500).json({ error: "internal_error" });
  }
});

// ---- Start server (Cloud Run uses PORT)
const port = Number(process.env.PORT) || 8080;
app.listen(port, () => console.log(`brifly-api listening on ${port}`));

import express from "express";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/jobs/create", async (req, res) => {
  const { client_id, connector_type, params = {} } = req.body;
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

  // Fire-and-forget n8n call
  fetch(process.env.N8N_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ job_id: job.id, client_id, connector_type, params }),
  }).catch(console.error);

  res.json({ job_id: job.id });
});

app.post("/ingest/connector-result", async (req, res) => {
  if (req.header("x-brifly-secret") !== process.env.N8N_SHARED_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const { job_id, connector_type, payload_json } = req.body;
  if (!job_id || !connector_type || !payload_json) {
    return res.status(400).json({ error: "job_id + connector_type + payload_json required" });
  }

  const { error } = await supabase
    .from("raw_connector_data")
    .insert({ job_id, connector_type, payload_json });

  if (error) return res.status(500).json({ error: error.message });

  await supabase
    .from("jobs")
    .update({ status: "pulled", finished_at: new Date().toISOString() })
    .eq("id", job_id);

  res.json({ ok: true });
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`brifly-api listening on ${port}`));

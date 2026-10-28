import { Hono } from "hono";

const app = new Hono<{ Bindings: Env }>();

app.get("/health", (c) => c.json({ service: "flaxia-auth", status: "ok" }));

export default app;

import { Router, type IRouter } from "express";
import {
  ClearAuditEventsResponse,
  ListAuditEventsResponse,
  VerifyAuditChainResponse,
} from "@workspace/api-zod";
import {
  clearUserAuditEvents,
  listAuditEvents,
  toAuditEventDto,
  verifyAuditChain,
} from "../lib/audit";
import { getAuthIdentity, requireAuth } from "../middlewares/auth";

const router: IRouter = Router();

router.get("/audit/events", requireAuth, async (_req, res): Promise<void> => {
  const { userId } = getAuthIdentity(res);
  const events = await listAuditEvents(userId);
  res.json(ListAuditEventsResponse.parse(events.map(toAuditEventDto)));
});

router.post("/audit/verify", requireAuth, async (_req, res): Promise<void> => {
  const { userId } = getAuthIdentity(res);
  const result = await verifyAuditChain(userId);
  res.json(VerifyAuditChainResponse.parse(result));
});

router.delete("/audit/events", requireAuth, async (_req, res): Promise<void> => {
  const { userId } = getAuthIdentity(res);
  const deletedEvents = await clearUserAuditEvents(userId);
  res.json(ClearAuditEventsResponse.parse({ deletedEvents }));
});

export default router;

import { and, desc, eq } from "drizzle-orm";
import { auditEventsTable, db, type AuditEventRow } from "@workspace/db";
import { sql } from "drizzle-orm";
import { createHash } from "node:crypto";

const GENESIS_HASH = "GENESIS";

function canonicalEvent(event: Pick<
  AuditEventRow,
  "id" | "userId" | "timestamp" | "category" | "decision" | "summary" | "previousHash"
>) {
  return JSON.stringify({
    id: event.id,
    userId: event.userId,
    timestamp: event.timestamp.toISOString(),
    category: event.category,
    decision: event.decision,
    summary: event.summary,
    previousHash: event.previousHash,
  });
}

function hashEvent(event: Parameters<typeof canonicalEvent>[0]): string {
  return createHash("sha256").update(canonicalEvent(event)).digest("hex");
}

async function appendAuditEventInTransaction(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  userId: number,
  category: string,
  decision: string,
  summary: string,
): Promise<AuditEventRow> {
  const [last] = await tx
    .select({ hash: auditEventsTable.hash })
    .from(auditEventsTable)
    .where(eq(auditEventsTable.userId, userId))
    .orderBy(desc(auditEventsTable.id))
    .limit(1);
  const [pending] = await tx
    .insert(auditEventsTable)
    .values({
      userId,
      category,
      decision,
      summary,
      previousHash: last?.hash ?? GENESIS_HASH,
      hash: "pending",
    })
    .returning();
  const hash = hashEvent(pending);
  const [saved] = await tx
    .update(auditEventsTable)
    .set({ hash })
    .where(eq(auditEventsTable.id, pending.id))
    .returning();
  return saved;
}

async function lockUserChain(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  userId: number,
): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${userId})`);
}

export async function appendAuditEvent(
  userId: number,
  category: string,
  decision: string,
  summary: string,
): Promise<AuditEventRow> {
  return db.transaction(async (tx) => {
    await lockUserChain(tx, userId);
    return appendAuditEventInTransaction(tx, userId, category, decision, summary);
  });
}

export async function listAuditEvents(userId: number): Promise<AuditEventRow[]> {
  return db
    .select()
    .from(auditEventsTable)
    .where(eq(auditEventsTable.userId, userId))
    .orderBy(desc(auditEventsTable.id))
    .limit(500);
}

export async function verifyAuditChain(userId: number) {
  const events = await db
    .select()
    .from(auditEventsTable)
    .where(eq(auditEventsTable.userId, userId))
    .orderBy(auditEventsTable.id);
  let previousHash = GENESIS_HASH;
  const errors: string[] = [];
  for (const event of events) {
    if (event.previousHash !== previousHash) {
      errors.push(`Event ${event.id}: previous hash does not match.`);
    }
    if (hashEvent(event) !== event.hash) {
      errors.push(`Event ${event.id}: event hash does not match.`);
    }
    previousHash = event.hash;
  }
  return { valid: errors.length === 0, checkedEvents: events.length, errors };
}

export async function clearUserAuditEvents(userId: number): Promise<number> {
  return db.transaction(async (tx) => {
    await lockUserChain(tx, userId);
    const removed = await tx
      .delete(auditEventsTable)
      .where(and(eq(auditEventsTable.userId, userId)))
      .returning({ id: auditEventsTable.id });
    await appendAuditEventInTransaction(
      tx,
      userId,
      "SESSION",
      "RESET",
      "Operator cleared this account's demo audit history and started a new chain.",
    );
    return removed.length;
  });
}

export function toAuditEventDto(event: AuditEventRow) {
  return {
    id: event.id,
    timestamp: event.timestamp.toISOString(),
    category: event.category,
    decision: event.decision,
    summary: event.summary,
    previousHash: event.previousHash,
    hash: event.hash,
  };
}

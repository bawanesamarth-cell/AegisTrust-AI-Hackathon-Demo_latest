import { createInsertSchema } from "drizzle-zod";
import { foreignKey, index, integer, pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";
import { z } from "zod/v4";
import { usersTable } from "./users";

export const auditEventsTable = pgTable(
  "aegistrust_audit_events",
  {
    id: serial("id").primaryKey(),
    userId: integer("user_id").notNull(),
    category: text("category").notNull(),
    decision: text("decision").notNull(),
    summary: text("summary").notNull(),
    previousHash: text("previous_hash").notNull(),
    hash: text("hash").notNull(),
    timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    foreignKey({
      columns: [table.userId],
      foreignColumns: [usersTable.id],
      name: "aegistrust_audit_events_user_id_fk",
    }).onDelete("cascade"),
    index("aegistrust_audit_events_user_id_id_idx").on(table.userId, table.id),
  ],
);

export const insertAuditEventSchema = createInsertSchema(auditEventsTable).omit({
  id: true,
  timestamp: true,
});
export type InsertAuditEvent = z.infer<typeof insertAuditEventSchema>;
export type AuditEventRow = typeof auditEventsTable.$inferSelect;

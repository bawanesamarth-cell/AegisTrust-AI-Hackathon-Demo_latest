import { compare, hash } from "bcryptjs";
import { eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import { db, usersTable } from "@workspace/db";
import {
  GetCurrentUserResponse,
  LoginUserBody,
  LoginUserResponse,
  RegisterUserBody,
  RegisterUserResponse,
} from "@workspace/api-zod";
import { appendAuditEvent } from "../lib/audit";
import { clearSessionCookie, getAuthIdentity, requireAuth, setSessionCookie } from "../middlewares/auth";

const router: IRouter = Router();
const BCRYPT_COST = 12;

function toAuthUser(user: typeof usersTable.$inferSelect) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: "operator" as const,
    createdAt: user.createdAt.toISOString(),
  };
}

router.post("/auth/register", async (req, res): Promise<void> => {
  const parsed = RegisterUserBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter a name, valid email, and password of at least 10 characters." });
    return;
  }
  const email = parsed.data.email.trim().toLowerCase();
  const [existing] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);
  if (existing) {
    res.status(409).json({ error: "An account with this email already exists." });
    return;
  }

  try {
    const passwordHash = await hash(parsed.data.password, BCRYPT_COST);
    const [user] = await db
      .insert(usersTable)
      .values({
        email,
        displayName: parsed.data.displayName.trim(),
        passwordHash,
        role: "operator",
      })
      .returning();
    setSessionCookie(res, { userId: user.id, email: user.email });
    await appendAuditEvent(
      user.id,
      "SESSION",
      "CREATED",
      "Operator account created and authenticated.",
    );
    res.status(201).json(RegisterUserResponse.parse(toAuthUser(user)));
  } catch (error) {
    const code =
      typeof error === "object" && error !== null && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code === "23505") {
      res.status(409).json({ error: "An account with this email already exists." });
      return;
    }
    req.log.error({ stage: "register" }, "Account registration failed");
    res.status(500).json({ error: "Could not create the account. Please try again." });
  }
});

router.post("/auth/login", async (req, res): Promise<void> => {
  const parsed = LoginUserBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Enter a valid email and password." });
    return;
  }
  const email = parsed.data.email.trim().toLowerCase();
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);
  const passwordMatches = user
    ? await compare(parsed.data.password, user.passwordHash)
    : false;
  if (!user || !passwordMatches) {
    res.status(401).json({ error: "Email or password is incorrect." });
    return;
  }

  setSessionCookie(res, { userId: user.id, email: user.email });
  await appendAuditEvent(user.id, "SESSION", "LOGIN", "Operator signed in.");
  res.json(LoginUserResponse.parse(toAuthUser(user)));
});

router.post("/auth/logout", (_req, res): void => {
  clearSessionCookie(res);
  res.json({ success: true });
});

router.get("/auth/me", requireAuth, async (_req, res): Promise<void> => {
  const { userId } = getAuthIdentity(res);
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .limit(1);
  if (!user) {
    clearSessionCookie(res);
    res.status(401).json({ error: "Account no longer exists." });
    return;
  }
  res.json(GetCurrentUserResponse.parse(toAuthUser(user)));
});

export default router;

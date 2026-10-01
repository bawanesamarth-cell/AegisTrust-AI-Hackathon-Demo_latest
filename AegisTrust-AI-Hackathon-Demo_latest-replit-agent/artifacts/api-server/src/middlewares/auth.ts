import { verify, sign, type JwtPayload } from "jsonwebtoken";
import type { RequestHandler, Response } from "express";

export const SESSION_COOKIE = "aegistrust_session";
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000;
const SESSION_ISSUER = "aegistrust";
const SESSION_AUDIENCE = "aegistrust-web";

export type AuthIdentity = { userId: number; email: string };

function sessionSecret(): string {
  const secret = process.env.SESSION_SECRET || (process.env.NODE_ENV !== "production" ? "aegistrust-dev-jwt-secret-key-32chars-minimum!" : undefined);
  if (!secret) throw new Error("SESSION_SECRET is not configured.");
  return secret;
}

function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/api",
    maxAge: SESSION_DURATION_MS,
  };
}

export function setSessionCookie(res: Response, user: AuthIdentity): void {
  const token = sign(
    { email: user.email },
    sessionSecret(),
    {
      subject: String(user.userId),
      issuer: SESSION_ISSUER,
      audience: SESSION_AUDIENCE,
      expiresIn: "8h",
      algorithm: "HS256",
    },
  );
  res.cookie(SESSION_COOKIE, token, cookieOptions());
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, cookieOptions());
}

export const requireAuth: RequestHandler = (req, res, next) => {
  const token = req.cookies?.[SESSION_COOKIE];
  if (typeof token !== "string" || token.length === 0) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  try {
    const decoded = verify(token, sessionSecret(), {
      algorithms: ["HS256"],
      issuer: SESSION_ISSUER,
      audience: SESSION_AUDIENCE,
    }) as JwtPayload;
    const userId = Number(decoded.sub);
    const email = typeof decoded.email === "string" ? decoded.email : "";
    if (!Number.isSafeInteger(userId) || userId <= 0 || !email) {
      res.status(401).json({ error: "Session is invalid or expired." });
      return;
    }
    res.locals.user = { userId, email } satisfies AuthIdentity;
    next();
  } catch {
    res.status(401).json({ error: "Session is invalid or expired." });
  }
};

export function getAuthIdentity(res: Response): AuthIdentity {
  const identity = res.locals.user as AuthIdentity | undefined;
  if (!identity) throw new Error("Authentication middleware did not set the user.");
  return identity;
}

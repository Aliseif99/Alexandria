/**
 * Authentication Middleware
 * JWT verification and role-based access control
 */

import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwtUtil";
import { ApiError } from "../utils/errorHandler";
import { sendError } from "../utils/formatters";
import logger from "../utils/logger";
import { IAuthPayload, UserRole } from "../types";

// Extend Express Request to include user info
declare global {
  namespace Express {
    interface Request {
      user?: IAuthPayload;
      ip?: string;
      userAgent?: string;
    }
  }
}

/**
 * Authenticate JWT token
 */
export function authenticate(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  try {
    const token = extractToken(req);

    if (!token) {
      sendError(res, "No token provided", 401);
      return;
    }

    const payload = verifyAccessToken(token);

    if (!payload) {
      sendError(res, "Invalid or expired token", 401);
      return;
    }

    req.user = payload;
    logger.debug("Token verified", { context: "auth.middleware" });
    next();
  } catch (error) {
    logger.error((error as Error).message, { context: "auth.middleware" });
    sendError(res, "Authentication failed", 401);
  }
}

/**
 * Authorize based on role
 */
export function authorize(...allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user) {
        sendError(res, "User not authenticated", 401);
        return;
      }

      if (!allowedRoles.includes(req.user.role)) {
        logger.warn("Unauthorized access attempt", {
          context: "auth.middleware",
          userId: req.user.id,
          userRole: req.user.role,
          allowedRoles,
        });
        sendError(res, "Insufficient permissions", 403);
        return;
      }

      next();
    } catch (error) {
      logger.error((error as Error).message, { context: "auth.middleware" });
      sendError(res, "Authorization failed", 403);
    }
  };
}

/**
 * Check if user is admin
 */
export function isAdmin(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  return authorize(UserRole.ADMIN, UserRole.SUPER_ADMIN)(req, res, next);
}

/**
 * Check if user is moderator
 */
export function isModerator(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  return authorize(UserRole.MODERATOR, UserRole.ADMIN, UserRole.SUPER_ADMIN)(
    req,
    res,
    next
  );
}

/**
 * Check if user is business owner
 */
export function isBusinessOwner(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  return authorize(
    UserRole.BUSINESS_OWNER,
    UserRole.ADMIN,
    UserRole.SUPER_ADMIN
  )(req, res, next);
}

/**
 * Optional authentication (doesn't fail if no token)
 */
export function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  try {
    const token = extractToken(req);

    if (token) {
      const payload = verifyAccessToken(token);
      if (payload) {
        req.user = payload;
      }
    }

    next();
  } catch (error) {
    logger.debug("Optional auth skipped", { context: "auth.middleware" });
    next();
  }
}

/**
 * Extract JWT token from request
 */
function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return null;
  }

  return parts[1];
}

/**
 * Get current user or throw error
 */
export function getCurrentUser(req: Request): IAuthPayload {
  if (!req.user) {
    throw ApiError.unauthorized("User not authenticated");
  }

  return req.user;
}

/**
 * Check if user owns resource
 */
export function checkOwnership(userId: string, resourceOwnerId: string): boolean {
  return userId === resourceOwnerId;
}

/**
 * Rate limiting middleware factory
 */
export function createRateLimiter(maxRequests: number, windowMs: number) {
  const requests = new Map<string, number[]>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.ip || "unknown";
    const now = Date.now();
    const requestTimes = requests.get(key) || [];

    // Remove old requests outside the window
    const filteredRequests = requestTimes.filter((time) => now - time < windowMs);

    if (filteredRequests.length >= maxRequests) {
      sendError(res, "Too many requests", 429);
      return;
    }

    filteredRequests.push(now);
    requests.set(key, filteredRequests);

    next();
  };
}

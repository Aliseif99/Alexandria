/**
 * Validation Schemas
 * Using Joi for request validation
 */

import Joi from "joi";
import { UserRole } from "./index";

// ==========================================
// Authentication Schemas
// ==========================================

export const registerSchema = Joi.object({
  name: Joi.string().min(2).max(100).required(),
  email: Joi.string().email().required(),
  phone: Joi.string()
    .regex(/^(\+?20)?1[0125][0-9]{8}$/)
    .required()
    .messages({
      "string.pattern.base": "Invalid Egyptian phone number",
    }),
  password: Joi.string()
    .min(8)
    .max(128)
    .required()
    .pattern(/[A-Z]/)
    .pattern(/[a-z]/)
    .pattern(/[0-9]/)
    .pattern(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)
    .messages({
      "string.pattern.base":
        "Password must contain uppercase, lowercase, number, and special character",
    }),
  confirmPassword: Joi.string()
    .valid(Joi.ref("password"))
    .required()
    .messages({
      "any.only": "Passwords do not match",
    }),
  role: Joi.string()
    .valid(UserRole.USER, UserRole.BUSINESS_OWNER)
    .optional()
    .default(UserRole.USER),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

export const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

export const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required(),
});

export const resetPasswordSchema = Joi.object({
  token: Joi.string().required(),
  password: Joi.string()
    .min(8)
    .max(128)
    .required()
    .pattern(/[A-Z]/)
    .pattern(/[a-z]/)
    .pattern(/[0-9]/)
    .pattern(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/),
  confirmPassword: Joi.string()
    .valid(Joi.ref("password"))
    .required(),
});

export const verifyEmailSchema = Joi.object({
  email: Joi.string().email().required(),
  code: Joi.string().length(6).required(),
});

export const verifyPhoneSchema = Joi.object({
  phone: Joi.string()
    .regex(/^(\+?20)?1[0125][0-9]{8}$/)
    .required(),
  code: Joi.string().length(6).required(),
});

// ==========================================
// User Schemas
// ==========================================

export const updateProfileSchema = Joi.object({
  name: Joi.string().min(2).max(100).optional(),
  bio: Joi.string().max(500).optional(),
  avatar: Joi.string().uri().optional(),
});

export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string()
    .min(8)
    .max(128)
    .required()
    .pattern(/[A-Z]/)
    .pattern(/[a-z]/)
    .pattern(/[0-9]/)
    .pattern(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/),
  confirmPassword: Joi.string()
    .valid(Joi.ref("newPassword"))
    .required(),
});

// ==========================================
// Place Schemas
// ==========================================

export const createPlaceSchema = Joi.object({
  name: Joi.string().min(2).max(255).required(),
  name_ar: Joi.string().min(2).max(255).required(),
  description: Joi.string().max(1000).optional(),
  description_ar: Joi.string().max(1000).optional(),
  categoryId: Joi.string().uuid().required(),
  districtId: Joi.string().uuid().required(),
  areaId: Joi.string().uuid().required(),
  address: Joi.string().max(500).required(),
  phone: Joi.string()
    .regex(/^(\+?20)?1[0125][0-9]{8}$/)
    .optional(),
  email: Joi.string().email().optional(),
  website: Joi.string().uri().optional(),
  latitude: Joi.number().min(-90).max(90).required(),
  longitude: Joi.number().min(-180).max(180).required(),
});

export const updatePlaceSchema = Joi.object({
  name: Joi.string().min(2).max(255).optional(),
  name_ar: Joi.string().min(2).max(255).optional(),
  description: Joi.string().max(1000).optional(),
  description_ar: Joi.string().max(1000).optional(),
  address: Joi.string().max(500).optional(),
  phone: Joi.string()
    .regex(/^(\+?20)?1[0125][0-9]{8}$/)
    .optional(),
  email: Joi.string().email().optional(),
  website: Joi.string().uri().optional(),
  latitude: Joi.number().min(-90).max(90).optional(),
  longitude: Joi.number().min(-180).max(180).optional(),
});

// ==========================================
// Category Schemas
// ==========================================

export const createCategorySchema = Joi.object({
  name: Joi.string().min(2).max(100).required(),
  name_ar: Joi.string().min(2).max(100).required(),
  slug: Joi.string()
    .lowercase()
    .regex(/^[a-z0-9-]+$/)
    .required(),
  description: Joi.string().max(500).optional(),
  description_ar: Joi.string().max(500).optional(),
  icon: Joi.string().optional(),
  color: Joi.string().regex(/^#[0-9A-F]{6}$/i).optional(),
});

export const updateCategorySchema = Joi.object({
  name: Joi.string().min(2).max(100).optional(),
  name_ar: Joi.string().min(2).max(100).optional(),
  description: Joi.string().max(500).optional(),
  description_ar: Joi.string().max(500).optional(),
  icon: Joi.string().optional(),
  color: Joi.string().regex(/^#[0-9A-F]{6}$/i).optional(),
});

// ==========================================
// District & Area Schemas
// ==========================================

export const createDistrictSchema = Joi.object({
  name: Joi.string().min(2).max(100).required(),
  name_ar: Joi.string().min(2).max(100).required(),
  description: Joi.string().max(500).optional(),
  description_ar: Joi.string().max(500).optional(),
  latitude: Joi.number().min(-90).max(90).required(),
  longitude: Joi.number().min(-180).max(180).required(),
});

export const createAreaSchema = Joi.object({
  name: Joi.string().min(2).max(100).required(),
  name_ar: Joi.string().min(2).max(100).required(),
  description: Joi.string().max(500).optional(),
  description_ar: Joi.string().max(500).optional(),
  districtId: Joi.string().uuid().required(),
  latitude: Joi.number().min(-90).max(90).required(),
  longitude: Joi.number().min(-180).max(180).required(),
});

// ==========================================
// Review Schemas
// ==========================================

export const createReviewSchema = Joi.object({
  content: Joi.string().min(10).max(1000).required(),
  rating: Joi.number().min(1).max(5).required(),
  placeId: Joi.string().uuid().required(),
  images: Joi.array().items(Joi.string().uri()).optional(),
});

export const updateReviewSchema = Joi.object({
  content: Joi.string().min(10).max(1000).optional(),
  rating: Joi.number().min(1).max(5).optional(),
});

// ==========================================
// Complaint Schemas
// ==========================================

export const createComplaintSchema = Joi.object({
  title: Joi.string().min(5).max(200).required(),
  description: Joi.string().min(10).max(2000).required(),
  categoryId: Joi.string().uuid().required(),
  districtId: Joi.string().uuid().required(),
  areaId: Joi.string().uuid().required(),
  latitude: Joi.number().min(-90).max(90).required(),
  longitude: Joi.number().min(-180).max(180).required(),
  priority: Joi.string()
    .valid("LOW", "MEDIUM", "HIGH", "CRITICAL")
    .optional()
    .default("MEDIUM"),
  images: Joi.array().items(Joi.string().uri()).optional(),
});

// ==========================================
// Pagination Schema
// ==========================================

export const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).optional().default(1),
  limit: Joi.number().integer().min(1).max(100).optional().default(10),
  sortBy: Joi.string().optional(),
  sortOrder: Joi.string().valid("asc", "desc").optional().default("desc"),
});

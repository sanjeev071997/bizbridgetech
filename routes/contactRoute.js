import express from "express";
import {
  createContact,
  getAllContacts,
  deleteContact,
} from "../controllers/contactController.js";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";

const router = express.Router();

// Public route
router.post("/create", createContact);

// Admin routes
router.get("/all", isAuthenticatedUser, isAdmin, getAllContacts);
router.delete("/:id", isAuthenticatedUser, isAdmin, deleteContact);

export default router;

import { Router } from "express";
import {
  createInvoice,
  recordPayment,
  getInvoice,
  getInvoiceStatement,
  sellerInvoice,
  runInterestCronNow,
} from "../controllers/invoiceController.js";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";

const router = Router();

// Create invoice from order
router.post("/", isAuthenticatedUser, createInvoice);

// Get invoice
router.get("/:id", isAuthenticatedUser, getInvoice);

// Full statement
router.get("/:id/statement", isAuthenticatedUser, getInvoiceStatement);

// Record a payment
router.post("/:id/pay", isAuthenticatedUser, recordPayment);

router.post("/get/invoice" ,isAuthenticatedUser, sellerInvoice);

// Manual interest run (protect in real app)
router.post("/cron/run", runInterestCronNow);

export default router;

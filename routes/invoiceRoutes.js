import { Router } from "express";
import {
  createInvoice,
  recordPayment,
  getInvoice,
  getInvoiceStatement,
  runInterestCronNow,
} from "../controllers/invoiceController.js";

const router = Router();

// Create invoice from order
router.post("/", createInvoice);

// Get invoice
router.get("/:id", getInvoice);

// Full statement
router.get("/:id/statement", getInvoiceStatement);

// Record a payment
router.post("/:id/pay", recordPayment);

// Manual interest run (protect in real app)
router.post("/cron/run", runInterestCronNow);

export default router;

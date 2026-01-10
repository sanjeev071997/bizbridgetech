import { Router } from "express";
import {
  createInvoice,
  recordPayment,
  getInvoice,
  getInvoiceStatement,
  sellerInvoice,
  runInterestCronNow,
  getSellerAllInvoices,
  getBuyerAllInvoices,
  updateCredit,
  updatePaymentStatus,
  deleteBankStatementEntry,
  getInvoiceBySellerBuyer,
  testMonthEndInterest
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

router.post("/get/invoice", isAuthenticatedUser, sellerInvoice);

// Manual interest run (protect in real app)
router.post("/cron/run", runInterestCronNow);

// Get all invoices for a seller
router.get("/seller/:id", isAuthenticatedUser, getSellerAllInvoices);

// Get all invoices for a buyer
router.get("/buyer/:id", isAuthenticatedUser, getBuyerAllInvoices);

// Buyer updates credit
router.patch("/buyer/credit/:id", isAuthenticatedUser, updateCredit);

// Seller updates paymentStatus
router.patch("/seller/status/:id", isAuthenticatedUser, updatePaymentStatus);

// Delete bank statement entry
router.delete("/buyer/bank-statement", isAuthenticatedUser, deleteBankStatementEntry);

// Get Invoice Seller and buyer (id)
router.post("/buyer", isAuthenticatedUser, getInvoiceBySellerBuyer) // Seller side 



// routes Test 
router.post('/test-month-end-interest', testMonthEndInterest);

export default router;

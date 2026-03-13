import express from "express";
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";
import { getSellerBilling } from "../controllers/billController.js"
import { triggerManualBilling } from '../utils/billingCron.js';
const router = express.Router();

router.get("/seller", isAuthenticatedUser, getSellerBilling)

router.post('/admin/trigger-billing', isAuthenticatedUser, isAdmin, triggerManualBilling);


export default router;

import express from "express";
import { msg91Webhook } from "../controllers/webhookController.js";
const router = express.Router();

router.post("/", msg91Webhook);

export default router;
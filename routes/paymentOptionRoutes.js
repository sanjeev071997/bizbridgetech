import express from "express";
import {
  createPaymentOption,
  getAllPaymentOptions,
  getPaymentOptionById,
  updatePaymentOption,
  deletePaymentOption,
  getPaymentOptionByUser,
  getPaymentOptionBybuyer
} from "../controllers/paymentOptionController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post("/", isAuthenticatedUser, createPaymentOption);

router.get("/", isAuthenticatedUser, getAllPaymentOptions);

router.get("/:id",isAuthenticatedUser, getPaymentOptionById);

router.put("/:id", isAuthenticatedUser, updatePaymentOption);

router.delete("/:id",isAuthenticatedUser, deletePaymentOption);

router.get("/user/:id", isAuthenticatedUser, getPaymentOptionByUser);

router.post("/buyer", isAuthenticatedUser, getPaymentOptionBybuyer);


export default router;

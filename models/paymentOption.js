import mongoose from "mongoose";

const paymentOptionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    paymentType: {
      type: String,
      enum: ["Cash", "Credit", "Both"],
      required: true,
    },

    cashPayment: {
      discountPercent: { type: Number, min: 0, max: 100 },
    },

    creditPayment: {
      creditPeriodDays: { type: Number, min: 0 }, // e.g. 30
      interestRatePerYear: { type: Number, min: 0 }, // e.g. 2 (%)
      interestStartAfterDays: { type: Number, min: 0, default: 30 }, //default 30
    },
  },
  { timestamps: true }
);

export default mongoose.model("PaymentOption", paymentOptionSchema);

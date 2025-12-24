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

    buyerCategory: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BuyerCategory",
      required: true,
    },

    creditPayment: {
      creditPeriodDays: { type: Number, min: 0 }, // e.g. 30.  30 day credit period 11:49. end month
      interestRatePerYear: { type: Number, min: 0 }, // e.g. 2 (%)
      // interestStartAfterDays: { type: Number, min: 0, default: 30 }, //default 30
      interestStartAfterDays: { 
        type: Number,
        default: function () {
          return this.creditPeriodDays;
        },
      },
    },
  },
  { timestamps: true }
);

export default mongoose.model("PaymentOption", paymentOptionSchema);

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

    // creditPayment: {
    //   creditPeriodDays: { type: Number, min: 0 }, // e.g. 30.  30 day credit period 11:49. end month
    //   interestRatePerYear: { type: Number, min: 0 }, // e.g. 2 (%)
    //   // interestStartAfterDays: { type: Number, min: 0, default: 30 }, //default 30
    //   interestStartAfterDays: { 
    //     type: Number,
    //     default: function () {
    //       return this.creditPeriodDays;
    //     },
    //   },
    // },

    // Update your paymentOptionModel.js:
creditPayment: {
  creditPeriodDays: { type: Number, min: 0 },
  interestRatePerYear: { type: Number, min: 0 },
  creditLimit: { type: Number, min: 0, default: 0 }, // Add this line
  // interestStartAfterDays: { 
  //   type: Number,
  //   default: function () {
  //     return this.creditPeriodDays;
  //   },
  // },
  interestStartAfterDays: { type: Number, min: 0 },
},
  },
  { timestamps: true }
);

// Add a pre-save middleware to set interestStartAfterDays
paymentOptionSchema.pre('save', function(next) {
  if (this.creditPayment && this.creditPayment.creditPeriodDays && !this.creditPayment.interestStartAfterDays) {
    this.creditPayment.interestStartAfterDays = this.creditPayment.creditPeriodDays;
  }
  next();
});


export default mongoose.model("PaymentOption", paymentOptionSchema);

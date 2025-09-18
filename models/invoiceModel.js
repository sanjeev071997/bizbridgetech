import mongoose from "mongoose";

const bankStatementEntrySchema = new mongoose.Schema({
  date:        { type: Date, required: true },
  description: { type: String, required: true },
  debit:       { type: Number, default: 0 },  // outstanding increases
  credit:      { type: Number, default: 0 },  // outstanding decreases
  balance:     { type: Number, required: true } // running outstanding after this entry
});

const invoiceSchema = new mongoose.Schema(
  {
    order:  { type: mongoose.Schema.Types.ObjectId, ref: "Order", required: true, unique: true },
    buyer:  { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },
    seller: { type: mongoose.Schema.Types.ObjectId, ref: "users" },

    amount: { type: Number, required: true, min: 0 },

    // pulled from PaymentOption.creditPayment
    creditPeriodDays:        { type: Number, default: 0 },
    interestRatePerYear:     { type: Number, default: 0 },
    interestStartAfterDays:  { type: Number, default: 0 },

    dueDate: { type: Date },     // invoiceDate + creditPeriodDays
    status:  { type: String, enum: ["Pending", "Overdue", "Paid"], default: "Pending" },
    paidAt:  { type: Date },

    // interest control
    interestAccrualStartDate: { type: Date }, // dueDate + interestStartAfterDays
    lastInterestAppliedOn:    { type: Date }, // last DATE (start-of-day) for which interest was added

    bankStatement: [bankStatementEntrySchema],
  },
  { timestamps: true }
);

export default mongoose.model("Invoice", invoiceSchema);

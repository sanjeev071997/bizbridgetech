import mongoose from "mongoose";

const bankStatementEntrySchema = new mongoose.Schema({
  date: { type: Date, required: true },
  description: { type: String, required: true },
  debit: { type: Number, default: 0 }, // outstanding increases
  credit: { type: Number, default: 0 }, // outstanding decreases
  balance: { type: Number, required: true }, // running outstanding after this entry
  paymentStatus: {
    type: String,
    enum: ["Pending", "Approved", "Cancelled"],
    default: "Pending",
  },
});

const invoiceSchema = new mongoose.Schema(
  {
    order: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Order",
      required: true,
      unique: true,
    },
    buyer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
    seller: { type: mongoose.Schema.Types.ObjectId, ref: "users" },

    amount: { type: Number, required: true, min: 0 },

    // pulled from PaymentOption.creditPayment
    creditPeriodDays: { type: Number, default: 0 },
    interestRatePerYear: { type: Number, default: 0 },
    interestStartAfterDays: { type: Number, default: 0 },

    dueDate: { type: Date }, // invoiceDate + creditPeriodDays
    status: {
      type: String,
      enum: ["Pending", "Overdue", "Paid"],
      default: "Pending",
    },
    paidAt: { type: Date },

    // interest control
    interestAccrualStartDate: { type: Date }, // dueDate + interestStartAfterDays
    lastInterestAppliedOn: { type: Date }, // last DATE (start-of-day) for which interest was added

    bankStatement: [bankStatementEntrySchema],

    invoiceNumber: {
      type: Number,
      unique: true,
    },
  },
  { timestamps: true }
);

// AUTO-INCREMENT INVOICE NUMBER
invoiceSchema.pre("validate", async function (next) {
  if (this.invoiceNumber) return next();

  try {
    const lastInvoice = await mongoose
      .model("Invoice")
      .findOne({ invoiceNumber: { $ne: null } }) // only valid ones
      .sort({ invoiceNumber: -1 })
      .lean();

    const lastNumber = lastInvoice?.invoiceNumber;

    this.invoiceNumber = Number.isFinite(lastNumber) ? lastNumber + 1 : 1; // fallback for first invoice

    next();
  } catch (err) {
    next(err);
  }
});

export default mongoose.model("Invoice", invoiceSchema);

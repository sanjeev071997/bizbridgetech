// models/bill.model.js
import mongoose from "mongoose";

const billSchema = new mongoose.Schema({
  sellerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'users',
    required: true,
    index: true
  },
  unverifiedBuyers: {
    type:Number,
    required: false,
  },
  verifiedBuyers: {
    type:Number,
    required: false,
  },
  totalDealers:{
    type:Number,
    required: false,
  },
  month: {
    type: Number,
    required: true,
    min: 0,
    max: 11
  },
  year: {
    type: Number,
    required: true
  },
  billingDate: {
    type: Date,
    required: true
  },
  dueDate: {
    type: Date,
    required: true
  },
  summary: {
    totalBuyers: {
      type: Number,
      required: true,
      default: 0
    },
    basePrice: {
      type: Number,
      required: true,
      default: 0
    },
    totalDealerPrice: {
      type: Number,
      required: true,
      default: 0
    },
    totalAmount: {
      type: Number,
      required: true,
      default: 0
    }
  },
  status: {
    type: String,
    enum: ['pending', 'paid', 'overdue', 'cancelled'],
    default: 'pending'
  },
  paidAt: Date,
  paymentMethod: String,
  invoiceNumber: String
}, {
  timestamps: true
});

// Unique index for seller per month (ek seller ka ek hi bill per month)
billSchema.index({ sellerId: 1, month: 1, year: 1 }, { unique: true });

// Pre-save hook to generate invoice number
billSchema.pre('save', async function(next) {
  if (!this.invoiceNumber) {
    const year = this.year.toString().slice(-2);
    const month = (this.month + 1).toString().padStart(2, '0');
    const count = await mongoose.model('Bill').countDocuments() + 1;
    this.invoiceNumber = `INV-${year}${month}-${count.toString().padStart(6, '0')}`;
  }
  next();
});

const Bill = mongoose.model('Bill', billSchema);
export default Bill;
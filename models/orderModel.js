import mongoose from "mongoose";

const processStepSchema = new mongoose.Schema({
  step: {
    type: String,
    enum: [
      "Enquiry Received",
      "Proforma Invoice",
      "Proforma Accepted",
      "Payment Received",
      "Invoice Uploaded",
      "Dispatch",
      "Delivered"
    ],
    required: true,
  },
  completed: { type: Boolean, default: false },
  completedAt: { type: Date }
});

const orderItemSchema = new mongoose.Schema({
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SellerProduct",
    required: true,
  },
  name: String,
  image: String,
  price: Number,
  mrp: Number,
  quantity: Number,
  discountPrice: Number,
  gstAmount: Number,
  finalPrice: Number,
   // Seller reference
  seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users", 
    required: false,
  },
});

const orderSchema = new mongoose.Schema(
  {
    buyer: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },
    items: [orderItemSchema],

    subTotal: { type: Number, required: true },
    discountFromPayment: { type: Number, default: 0 },
    total: { type: Number, required: true },

    paymentOption: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: "PaymentOption", 
      required: false 
    },

    orderStatus: {
      type: String,
      enum: ["Pending", "Processing", "Completed", "Cancelled"],
      default: "Pending",
    },

    processFlow: [processStepSchema],
  },
  { timestamps: true }
);

const Order = mongoose.model("Order", orderSchema);
export default Order;


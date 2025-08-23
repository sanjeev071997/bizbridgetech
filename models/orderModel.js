import mongoose from "mongoose";

const orderItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SellerProduct",
    required: true
  },
  quantity: {
    type: Number,
    required: true,
    min: 1
  },
  price: {
    type: Number,
    required: true
  },
  amount: {
    type: Number,
    required: true
  }
}, { _id: false });

const orderSchema = new mongoose.Schema({
  items: [orderItemSchema],   // 🔹 multiple products per order
  totalAmount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ["Pending", "Shipped", "Delivered", "Cancelled"],
    default: "Pending"
  },
  paymentOption: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "PaymentOption",
    required: true
  },
  buyer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

const Order = mongoose.model("Order", orderSchema);

export default Order;

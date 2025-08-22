import mongoose from "mongoose";

const cartItemSchema = new mongoose.Schema(
  {
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "SellerProduct",
      required: true,
    },
    quantity: {
      type: Number,
      required: true,
      min: 1,
      default: 1,
    },
    price: {
      type: Number,
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    image: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

const cartSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
    items: [cartItemSchema],
    total: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

// Cart total की automatic calculation
cartSchema.pre("save", function (next) {
  this.total = this.items.reduce(
    (total, item) => total + item.price * item.quantity,
    0
  );
  next();
});

const Cart = mongoose.model("Cart", cartSchema);
export default Cart;

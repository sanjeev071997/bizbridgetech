// import mongoose from "mongoose";

// const cartItemSchema = new mongoose.Schema(
//   {
//     product: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "SellerProduct",
//       required: true,
//     },
//     quantity: {
//       type: Number,
//       required: true,
//       min: 1,
//       default: 1,
//     },
//     price: {
//       type: Number,
//       required: true,
//     },
//     name: {
//       type: String,
//       required: true,
//     },
//     image: {
//       type: String,
//       required: true,
//     },
//   },
//   { timestamps: true }
// );

// const cartSchema = new mongoose.Schema(
//   {
//     user: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "users",
//       required: true,
//     },
//     items: [cartItemSchema],
//     paymentOption: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "PaymentOption",
//       required: false,
//     },
//     total: {
//       type: Number,
//       default: 0,
//     },
//   },
//   { timestamps: true }
// );

// // Cart total automatic calculation
// cartSchema.pre("save", function (next) {
//   this.total = this.items.reduce(
//     (total, item) => total + item.price * item.quantity,
//     0
//   );
//   next();
// });

// const Cart = mongoose.model("Cart", cartSchema);
// export default Cart;

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
    mrp: {
      type: Number,
      required: true,
    },
    discountPrice: {
      type: Number,
      default: 0, // product discount ke baad
    },
    gstAmount: {
      type: Number,
      default: 0, // gst amount
    },
    finalPrice: {
      type: Number,
      default: 0, // per item after discount + gst
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
    paymentOption: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PaymentOption",
      required: false,
    },
    subTotal: {
      type: Number,
      default: 0,
    },
    discountFromPayment: {
      type: Number,
      default: 0,
    },
    total: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

// 🔹 Auto calculation function
cartSchema.methods.calculateTotals = async function () {
  let subTotal = 0;

  for (let item of this.items) {
    // step 1: discount on product MRP
    const discountPercent = 35; // TODO: agar product schema me ho to wahi le lo
    item.discountPrice = item.mrp - (item.mrp * discountPercent) / 100;

    // step 2: gst after discount
    const gstPercent = 18; // TODO: agar category wise ho to wahi le lo
    item.gstAmount = (item.discountPrice * gstPercent) / 100;

    // step 3: final price per quantity
    item.finalPrice = (item.discountPrice + item.gstAmount) * item.quantity;

    subTotal += item.finalPrice;
  }

  this.subTotal = subTotal;

  // step 4: check payment option (flexible for Cash or Both)
  let paymentDiscount = 0;
  if (this.paymentOption) {
    const option = await mongoose.model("PaymentOption").findById(this.paymentOption);

    if (option?.cashPayment?.discountPercent) {
      paymentDiscount = (subTotal * option.cashPayment.discountPercent) / 100;
    }
  }

  this.discountFromPayment = paymentDiscount;
  this.total = subTotal - paymentDiscount;
};

const Cart = mongoose.model("Cart", cartSchema);
export default Cart;

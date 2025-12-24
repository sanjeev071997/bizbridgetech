// // import mongoose from "mongoose";

// // const processStepSchema = new mongoose.Schema({
// //   step: {
// //     type: String,
// //     enum: [
// //       "Enquiry Received",
// //       "Proforma Invoice",
// //       "Proforma Accepted",
// //       "Payment QR Generated",
// //       "Payment Received",
// //       "Invoice Uploaded",
// //       "Dispatch",
// //       "Delivered",
// //     ],
// //     required: true,
// //   },
// //   completed: { type: Boolean, default: false },
// //   completedAt: { type: Date },
// //   qrCodeUrl: { type: String }, // if QR is generated at this step
// //   // NEW FIELD for credit payments
// //   creditDetails: {
// //     creditPeriodDays: Number,
// //     interestRatePerMonth: Number,
// //     interestStartAfterDays: Number,
// //     paymentType: String, // 'Credit' or 'Debit'
// //     totalAmount: Number,
// //     dueDate: Date,
// //     interestStartDate: Date,
// //   },
// // });

// // const orderItemSchema = new mongoose.Schema({
// //   product: {
// //     type: mongoose.Schema.Types.ObjectId,
// //     ref: "SellerProduct",
// //     required: true,
// //   },
// //   name: String,
// //   image: String,
// //   price: Number,
// //   mrp: Number,
// //   quantity: Number,
// //   discountPrice: Number,
// //   gstAmount: Number,
// //   finalPrice: Number,
// //    // Seller reference
// //   seller: {
// //     type: mongoose.Schema.Types.ObjectId,
// //     ref: "users", 
// //     required: false,
// //   },
// //    category: {
// //         _id: { type: mongoose.Schema.Types.ObjectId },
// //         name: { type: String },
// //         gst: { type: String },
// //       },
// // });

// // const orderSchema = new mongoose.Schema(
// //   {
// //     buyer: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },
// //     items: [orderItemSchema],

// //     subTotal: { type: Number, required: true },
// //     discountFromPayment: { type: Number, default: 0 },
// //     total: { type: Number, required: true },

// //     paymentOption: { 
// //       type: mongoose.Schema.Types.ObjectId, 
// //       ref: "PaymentOption", 
// //       required: false 
// //     },

// //     orderStatus: {
// //       type: String,
// //       enum: ["Pending", "Processing", "Completed", "Cancelled"],
// //       default: "Pending",
// //     },

// //     processFlow: [processStepSchema],

// //     qrCodeData: { type: String }, // QR code base64 or URL
// //   },
// //   { timestamps: true }
// // );

// // const Order = mongoose.model("Order", orderSchema);
// // export default Order;


// import mongoose from "mongoose";

// const processStepSchema = new mongoose.Schema({
//   step: {
//     type: String,
//     enum: [
//       "Enquiry Received",
//       "Proforma Invoice",
//       "Proforma Accepted",
//       "Payment QR Generated",
//       "Payment Received",
//       "Invoice Uploaded",
//       "Dispatch",
//       "Delivered",
//     ],
//     required: true,
//   },
//   completed: { type: Boolean, default: false },
//   completedAt: { type: Date },
//   qrCodeUrl: { type: String },

//   creditDetails: {
//     creditPeriodDays: Number,
//     interestRatePerYear: Number,
//     interestStartAfterDays: Number,
//     paymentType: String,
//     totalAmount: Number,
//     dueDate: Date,
//     interestStartDate: Date,
//   },
// });

// // 🔥 ITEM LEVEL SCHEMA (MULTIPLE PRODUCT SUPPORT)
// const orderItemSchema = new mongoose.Schema({
//   product: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: "SellerProduct",
//     required: true,
//   },
//   name: String,
//   image: String,

//   price: Number,
//   mrp: Number,
//   quantity: Number,
//   discountPrice: Number,

//   gstAmount: Number,          // GST per unit
//   finalPrice: Number,         // price + gst per unit
//   // subTotal: Number,           // finalPrice * quantity (IMPORTANT)

//   // Item level discount (if needed)
//   // discountFromPayment: {
//   //   type: Number,
//   //   default: 0,
//   // },

//   seller: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: "users",
//     required: false,
//   },

//   category: {
//     _id: { type: mongoose.Schema.Types.ObjectId },
//     name: { type: String },
//     gst: { type: String },
//   },
// });

// // 🔥 ORDER LEVEL SCHEMA
// const orderSchema = new mongoose.Schema(
//   {
//     buyer: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },

//     items: [orderItemSchema], // multiple products

//     // Order Level Summary
//     subTotal: { type: Number, required: true }, // items subtotal sum
//     discountFromPayment: { type: Number, default: 0 },
//     total: { type: Number, required: true },

//     paymentOption: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "PaymentOption",
//       required: false,
//     },

//     selectPaymentType: {
//       type: String,
//       required: false,
//     },
    
//     orderStatus: {
//       type: String,
//       enum: ["Pending", "Processing", "Completed", "Cancelled"],
//       default: "Pending",
//     },

//     processFlow: [processStepSchema],

//     qrCodeData: { type: String },
//   },
//   { timestamps: true }
// );

// const Order = mongoose.model("Order", orderSchema);
// export default Order;

// import mongoose from "mongoose";

// const processStepSchema = new mongoose.Schema({
//   step: {
//     type: String,
//     enum: [
//       "Enquiry Received",
//       "Proforma Invoice",
//       "Proforma Accepted",
//       "Payment QR Generated",
//       "Payment Received",
//       "Invoice Uploaded",
//       "Dispatch",
//       "Delivered",
//     ],
//     required: true,
//   },
//   completed: { type: Boolean, default: false },
//   completedAt: { type: Date },
//   qrCodeUrl: { type: String }, // if QR is generated at this step
//   // NEW FIELD for credit payments
//   creditDetails: {
//     creditPeriodDays: Number,
//     interestRatePerYear: Number,
//     interestStartAfterDays: Number,
//     paymentType: String, // 'Credit' or 'Debit'
//     totalAmount: Number,
//     dueDate: Date,
//     interestStartDate: Date,
//   },
// });

// const orderItemSchema = new mongoose.Schema({
//   product: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: "SellerProduct",
//     required: true,
//   },
//   name: String,
//   image: String,
//   price: Number,
//   mrp: Number,
//   quantity: Number,
//   discountPrice: Number,
//   gstAmount: Number,
//   finalPrice: Number,
//    // Seller reference
//   seller: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: "users", 
//     required: false,
//   },
//    category: {
//         _id: { type: mongoose.Schema.Types.ObjectId },
//         name: { type: String },
//         gst: { type: String },
//       },
// });

// const orderSchema = new mongoose.Schema(
//   {
//     buyer: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },
//     items: [orderItemSchema],

//     subTotal: { type: Number, required: true },
//     discountFromPayment: { type: Number, default: 0 },
//     total: { type: Number, required: true },

//     paymentOption: { 
//       type: mongoose.Schema.Types.ObjectId, 
//       ref: "PaymentOption", 
//       required: false 
//     },

//     orderStatus: {
//       type: String,
//       enum: ["Pending", "Processing", "Completed", "Cancelled"],
//       default: "Pending",
//     },

//     processFlow: [processStepSchema],

//     qrCodeData: { type: String }, // QR code base64 or URL
//   },
//   { timestamps: true }
// );

// const Order = mongoose.model("Order", orderSchema);
// export default Order;


import mongoose from "mongoose";

const processStepSchema = new mongoose.Schema({
  step: {
    type: String,
    enum: [
      "Enquiry Received",
      "Proforma Invoice",
      "Proforma Accepted",
      "Payment QR Generated",
      "Payment Received",
      "Invoice Uploaded",
      "Dispatch",
      "Delivered",
    ],
    required: true,
  },
  completed: { type: Boolean, default: false },
  completedAt: { type: Date },
  qrCodeUrl: { type: String },

  creditDetails: {
    creditPeriodDays: Number,
    interestRatePerYear: Number,
    interestStartAfterDays: Number,
    paymentType: String,
    totalAmount: Number,
    dueDate: Date,
    interestStartDate: Date,
  },
});

// 🔥 ITEM LEVEL SCHEMA (MULTIPLE PRODUCT SUPPORT)
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

  gstAmount: Number,          // GST per unit
  finalPrice: Number,         // price + gst per unit
  // subTotal: Number,           // finalPrice * quantity (IMPORTANT)

  // Item level discount (if needed)
  // discountFromPayment: {
  //   type: Number,
  //   default: 0,
  // },

  seller: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    required: false,
  },

  category: {
    _id: { type: mongoose.Schema.Types.ObjectId },
    name: { type: String },
    gst: { type: String },
  },
});

// 🔥 ORDER LEVEL SCHEMA
const orderSchema = new mongoose.Schema(
  {
    buyer: { type: mongoose.Schema.Types.ObjectId, ref: "users", required: true },

    items: [orderItemSchema], // multiple products

    // Order Level Summary
    subTotal: { type: Number, required: true }, // items subtotal sum
    discountFromPayment: { type: Number, default: 0 },
    total: { type: Number, required: true },

    paymentOption: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PaymentOption",
      required: false,
    },

    selectPaymentType: {
      type: String,
      required: false,
    },
    
    orderStatus: {
      type: String,
      enum: ["Pending", "Processing", "Completed", "Cancelled"],
      default: "Pending",
    },

    processFlow: [processStepSchema],

    qrCodeData: { type: String },
  },
  { timestamps: true }
);

const Order = mongoose.model("Order", orderSchema);
export default Order;
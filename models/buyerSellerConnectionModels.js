// import mongoose from "mongoose";

// const buyerSellerConnectionSchema = new mongoose.Schema(
//   {
//     seller: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "users", // seller reference
//       required: true,
//     },
//     buyer: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "users", // buyer reference
//     },
//     buyerEmail: {
//       type: String,
//       required: false,
//     },
//     buyerPhone: {
//       type: String,
//       required: false,
//     },
//     buyerCategory: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: "BuyerCategory",
//       required: true,
//     },
//     status: {
//       type: String,
//       enum: ["Pending", "Accepted", "Rejected"], // only these values allowed
//       default: "Pending",
//     },
//   },
//   {
//     timestamps: true,
//   }
// );

// const BuyerSellerConnection = mongoose.model("BuyerSellerConnection", buyerSellerConnectionSchema);

// export default BuyerSellerConnection;

import mongoose from "mongoose";
const buyerSellerConnectionSchema = new mongoose.Schema(
  {
    seller: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
    buyer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      default: null, 
    },
    buyerPhone: {
      type: String,
      required: true, 
    },
    buyerCategory: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BuyerCategory",
      required: true,
    },
    status: {
      type: String,
      enum: ["Pending", "Accepted", "Rejected"],
      default: "Accepted", 
    },
  },
  { timestamps: true }
);

const BuyerSellerConnection = mongoose.model("BuyerSellerConnection", buyerSellerConnectionSchema);

export default BuyerSellerConnection;
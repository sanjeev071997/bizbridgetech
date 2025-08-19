import mongoose from "mongoose";

const sellerProductSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    image: {
      type: String,
      required: true,
    },
    cloudinaryId: {
      type: String,
      required: false,
    },
    price: {
      type: Number,
      required: true,
    },  
    category: {                                        // Product category -> SellerCategory
      type: mongoose.Schema.Types.ObjectId,
      ref: "SellerCategory",
      required: true,
    },
    buyerCategory: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BuyerCategory",
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
  },
  { timestamps: true }
);

const SellerProduct = mongoose.model("SellerProduct", sellerProductSchema);
export default SellerProduct;

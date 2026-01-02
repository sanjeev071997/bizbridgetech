import mongoose from "mongoose";

const sellerProductSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    image: {
      type: String,
      required: false,
    },
    cloudinaryId: {
      type: String,
      required: false,
    },
    mrp: {
      type: Number,
      required: true,
    },
    // stock: {
    //   type: Number,
    //   required: true,
    //   min: 0,
    // },
    unit: {
    type: String,
    required: false,
    },
    description: {
      type: String,
      required: false,
    },
    specifications: {
      type: Object,
      required: false,
    },
    category: {
      // Product category -> SellerCategory
      type: mongoose.Schema.Types.ObjectId,
      ref: "SellerCategory",
      required: true,
    },

    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    productVisibility: [
      {
        buyerCategory: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "BuyerCategory",
          required: true,
        },
        visible: {
          type: Boolean,
          default: true,
        },
        price: {
          type: Number,
          required: true,
        },

         isPriceManuallySet: {  // NEW FIELD
      type: Boolean,
      default: false,
    },
    lastPriceUpdate: {  // NEW FIELD
      type: Date,
      default: Date.now,
    }
      },
    ],
  },
  { timestamps: true }
);

const SellerProduct = mongoose.model("SellerProduct", sellerProductSchema);
export default SellerProduct;

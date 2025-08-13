import mongoose from "mongoose";

const advertisementSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },
    offers: {
      type: String,
      required: true,
      trim: true,
    },
    image: {
      type: String,
      required: false,
    },
    cloudinaryId: {
      type: String,
      required: false,
    },
    category: [
      {
        type: mongoose.Schema.Types.Mixed, 
        // Can be ObjectId (Category) or string "All"
        ref: "SellerCategory",
      }
    ],
  },
  {
    timestamps: true,
  }
);

const Advertisement = mongoose.model("Advertisement", advertisementSchema);

export default Advertisement;

import mongoose from "mongoose";

const brandsSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
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
  },
  {
    timestamps: true,
  }
);

const Brands = mongoose.model("Brands", brandsSchema);

export default Brands;

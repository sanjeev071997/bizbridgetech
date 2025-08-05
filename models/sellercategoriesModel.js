import mongoose from 'mongoose';

const sellerCategorySchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'users',
      required: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    gst: {
      type: String,
      required: true,
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

const SellerCategory = mongoose.model('SellerCategory', sellerCategorySchema);

export default SellerCategory;

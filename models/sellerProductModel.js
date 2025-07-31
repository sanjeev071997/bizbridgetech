import mongoose from 'mongoose';

const sellerProductSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  image: {
    type: String,  
    required: true,
  },
  pricing: {
    type: Number,
    required: true,
  },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SellerCategory',
    required: true,
  },
}, { timestamps: true });

const SellerProduct = mongoose.model('SellerProduct', sellerProductSchema);
export default SellerProduct;

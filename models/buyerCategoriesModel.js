 import mongoose from 'mongoose';
 
 const buyerCategorySchema = new mongoose.Schema(
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
     discount: {
       type: String,
       required: true,
       trim: true,
     },
     color: {
      type: String,
      required: false
     }
   },
   {
     timestamps: true,
   }
 );
 
 const BuyerCategory = mongoose.model('BuyerCategory', buyerCategorySchema);
 
 export default BuyerCategory;
 
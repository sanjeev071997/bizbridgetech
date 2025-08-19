import mongoose from "mongoose";

const schemeSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    title: {
      type: String,
      required: true,
      trim: true,
    },

    type: {
      type: String,
      required: true,
      trim: true,
    },

    details: {
      type: String,
      required: true,
      trim: true,
    },
    // buyersReached: {
    //   type: Number,
    //   default: 0,
    // },

    active: {
      type: Boolean,
      default: true,
    },
    
  },
  { timestamps: true }
);

export default mongoose.model("Scheme", schemeSchema);

import mongoose from "mongoose";

const supportSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    subject: {
      type: String,
      required: [true, "Subject is required"],
    },

    description: {
      type: String,
      required: [true, "Description is required"],
    },

  },
  {
    timestamps: true, 
  }
);

const Support = mongoose.model("Support", supportSchema);

export default Support;

import mongoose from "mongoose";

const contactSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: false,
      trim: true,
      lowercase: true,
    },

    phone: {
      type: String,
      required: true,
      trim: true,
    },

    message: {
      type: String,
      required: false,
      trim: true,
    },

    business: {
      type: String,
      trim: true,
    },
    city: {
      type: String,
      trim: true,
    },
    planId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Plan",
      required: false,
    },
  },
  {
    timestamps: true,
  },
);

const contact = mongoose.model("contact", contactSchema);

export default contact;

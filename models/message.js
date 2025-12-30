import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    conversationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Conversation",
      required: true,
    },

    sender: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    receiver: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "users",
      required: true,
    },

    text: {
      type: String,
      required: true,
    },

    isRead: {
      type: Boolean,
      default: false,
    },
    
    mode: {
      type: String,
      enum: ["seller", "buyer"],
      required: true, // Save the sender's current mode
    },
  },
  { timestamps: true }
);

export default mongoose.model("Message", messageSchema);
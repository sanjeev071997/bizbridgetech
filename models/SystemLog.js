// models/SystemLog.js

import mongoose from "mongoose";

const systemLogSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: String,
});

export default mongoose.model("SystemLog", systemLogSchema);
import Support from "../models/supportModel.js";
import Errorhandler from '../utils/Errorhandler.js';
import catchAsyncErrors from '../middlewares/catchAsyncErrors.js';

// Create new support ticket
export const createSupport = catchAsyncErrors(async (req, res, next) => {
  try {
    const { subject, description } = req.body;

    const newSupport = await Support.create({ subject, description, user: req.user._id });

    res.status(201).json({
      success: true,
      message: "Support ticket created successfully",
      data: newSupport,
    });
  } catch (error) {
    next(new Errorhandler("Failed to create support ticket", 500));
  }
});

// Get all support tickets
export const getAllSupport = catchAsyncErrors(async (req, res, next) => {
  try {
    const supports = await Support.find().sort({ createdAt: -1 }).populate("user", "name phone")
    res.status(200).json({
      success: true,
      data: supports,
    });
  } catch (error) {
    next(new Errorhandler("Failed to fetch support tickets", 500));
  }
});

// Get Single support userId
export const getSupportByUserId = catchAsyncErrors(async (req, res, next) => {
  try {
    const supports = await Support.find({ user: req.user._id }).sort({ createdAt: -1 });
    
    if (!supports || supports.length === 0) {
      return next(new Errorhandler("No support tickets found for this user", 404));
    }

    res.status(200).json({
      success: true,
      data: supports,
    });
  } catch (error) {
    next(new Errorhandler("Failed to fetch support tickets for user", 500));
  }
});

// Delete support
export const deleteSupport = catchAsyncErrors(async (req, res, next) => {
  try {
    const { id } = req.body;

    const support = await Support.findByIdAndDelete(id);

    if (!support) {
      return next(new Errorhandler("Support ticket not found", 404));
    }

    res.status(200).json({
      success: true,
      message: "Support ticket deleted successfully",
      data: support,
    });

  } catch (error) {
    next(new Errorhandler("Failed to delete support ticket", 500));
  }
});


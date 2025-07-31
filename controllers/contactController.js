import Contact from "../models/contactModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Submit Contact Form (Public)
export const createContact = catchAsyncErrors (async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;

    if (!name || !email || !phone || !message) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const contact = await Contact.create({ name, email, phone, message });

    return res.status(201).json({
      success: true,
      message: "Contact message submitted successfully",
      data: contact,
    });
  } catch (error) {
     return next(new Errorhandler(error.message, 500));
  }
});

// Get All Contacts (Admin Only)
export const getAllContacts = catchAsyncErrors (async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      message: "All contact messages retrieved",
      data: contacts,
    });
  } catch (error) {
     return next(new Errorhandler(error.message, 500));
  }
});

// Delete Contact by ID (Admin Only)
export const deleteContact = catchAsyncErrors(async (req, res) => {
  try {
    const { id } = req.params;

    const contact = await Contact.findByIdAndDelete(id);

    if (!contact) {
      return res.status(404).json({
        success: false,
        message: "Contact not found",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Contact deleted successfully",
    });
  } catch (error) {
    return next(new Errorhandler(error.message, 500));
  }
});

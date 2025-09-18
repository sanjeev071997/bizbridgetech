import CompanyFeed from "../models/companyfeedsModel.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import cloudinary from "../utils/cloudinary.js";
import ErrorHandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Function to handle base64 image uploads
const uploadBase64Image = async (base64Image) => {
  try {
    const result = await cloudinary.uploader.upload(base64Image, {
      folder: "CompanyFeeds",
    });
    return {
      image: result.secure_url,
      cloudinaryId: result.public_id,
    };
  } catch (error) {
    throw new Error("Error uploading base64 image");
  }
};

// Create Feed 
export const createFeed = catchAsyncErrors(async (req, res, next) => {
  let { title, description, image } = req.body;

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    // Upload Image
    if (image && image.startsWith("data:image")) {
      // Base64 format
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      // Normal image URL or path
      const result = await cloudinary.uploader.upload(image, {
        folder: "CompanyFeeds",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    // If no image uploaded successfully but image was sent
    if (image && !imageUrl) {
      return next(new ErrorHandler("Image upload failed", 400));
    }

    // Save feed
    const feed = await CompanyFeed.create({
      user: req.user._id,
      title,
      description,
      image: imageUrl || null,
      cloudinaryId: cloudinaryId || null,
    });

    res.status(201).json({
      success: true,
      message: "Feed created successfully",
      data: feed,
    });
  } catch (error) {
    return next(
      new Errorhandler("Error processing feed upload or creation", 500)
    );
  }
});


// Get All Feeds
export const getAllFeeds = catchAsyncErrors(async (req, res, next) => {
  try {
    const buyerId = req.user._id; // current logged-in user

    // Step 1: Find all connections where this user is buyer
    const connections = await BuyerSellerConnection.find({
      buyer: buyerId,
      status: "Accepted",
    }).select("seller");

    const sellerIds = connections.map((c) => c.seller);

    // Step 2: Include current user also
    sellerIds.push(buyerId);

    // Step 3: Find feeds from connected sellers + current user
    const feeds = await CompanyFeed.find({
      user: { $in: sellerIds },
    })
      .populate("user", "name email")
      .populate("comments.user", "name email")
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: feeds.length,
      data: feeds,
    });
  } catch (error) {
    next(error);
  }
});


// Get Feed By ID (only if seller is connected with buyer OR current user)
export const getFeedById = catchAsyncErrors(async (req, res, next) => {
  try {
    const buyerId = req.user._id; // current logged-in user
    const feedId = req.params.id;

    // Step 1: find all connections where this user is buyer
    const connections = await BuyerSellerConnection.find({
      buyer: buyerId,
      status: "Accepted",
    }).select("seller");

    const sellerIds = connections.map((c) => c.seller);

    // Step 2: include current user also
    sellerIds.push(buyerId);

    // Step 3: find feed by ID from connected sellers + current user
    const feed = await CompanyFeed.findOne({
      _id: feedId,
      user: { $in: sellerIds },
    })
      .populate("user", "name email")
      .populate("comments.user", "name email");

    if (!feed) {
      return next(
        new ErrorHandler("Feed not found or not accessible", 404)
      );
    }

    res.status(200).json({
      success: true,
      data: feed,
    });
  } catch (error) {
    next(error);
  }
});


// Update Feed
export const updateFeed = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params; // feed id
  const { text, image } = req.body;

  try {
    const feed = await CompanyFeed.findById(id);
    if (!feed) {
      return next(new ErrorHandler("Feed not found", 404));
    }

    // Ensure only owner can update
    if (feed.user.toString() !== req.user._id.toString()) {
      return next(
        new ErrorHandler("You can update only your own feed", 403)
      );
    }

    // Update image if provided
    let imageUrl = feed.image;
    let cloudinaryId = feed.cloudinaryId;

    if (image && image.startsWith("data:image")) {
      // base64 image
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      // normal file/image url
      const result = await cloudinary.uploader.upload(image, {
        folder: "CompanyFeeds",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    // Update fields
    feed.text = text || feed.text;
    feed.image = imageUrl;
    feed.cloudinaryId = cloudinaryId;

    await feed.save();

    res.status(200).json({
      success: true,
      message: "Feed updated successfully",
      data: feed,
    });
  } catch (error) {
    return next(new ErrorHandler("Error updating feed", 500));
  }
});

// Delete Feed
export const deleteFeed = catchAsyncErrors(async (req, res, next) => {
  try {
    const feed = await CompanyFeed.findById(req.params.id);

    if (!feed) {
      return next(new ErrorHandler("Feed not found", 404));
    }

    // Only feed owner can delete
    if (feed.user.toString() !== req.user._id.toString()) {
      return next(
        new ErrorHandler("You are not authorized to delete this feed", 403)
      );
    }

    // Delete image from Cloudinary if exists
    if (feed.cloudinaryId) {
      await cloudinary.uploader.destroy(feed.cloudinaryId);
    }

    // Delete feed from DB
    await feed.deleteOne();

    res.status(200).json({
      success: true,
      message: "Feed deleted successfully",
    });
  } catch (error) {
    return next(new ErrorHandler("Error deleting feed", 500));
  }
});



// Like Feed 
export const likeFeed = catchAsyncErrors(async (req, res, next) => {
  const feed = await CompanyFeed.findById(req.params.id);
  if (!feed) {
    return next(new ErrorHandler("Feed not found", 404));
  }

  const userId = req.user._id;

  if (feed.likes.includes(userId)) {
    return next(new ErrorHandler("Already liked this feed", 400));
  }

  feed.likes.push(userId);
  await feed.save();

  res.status(200).json({
    success: true,
    message: "Feed liked successfully",
    likesCount: feed.likes.length,
  });
});

// Unlike Feed 
export const unlikeFeed = catchAsyncErrors(async (req, res, next) => {
  const feed = await CompanyFeed.findById(req.params.id);
  if (!feed) {
    return next(new ErrorHandler("Feed not found", 404));
  }

  const userId = req.user._id;

  if (!feed.likes.includes(userId)) {
    return next(new ErrorHandler("You have not liked this feed", 400));
  }

  feed.likes = feed.likes.filter(
    (like) => like.toString() !== userId.toString()
  );

  await feed.save();

  res.status(200).json({
    success: true,
    message: "Feed unliked successfully",
    likesCount: feed.likes.length,
  });
});

// Add Comment 
export const addComment = catchAsyncErrors(async (req, res, next) => {
  const { text } = req.body;
  const feed = await CompanyFeed.findById(req.params.id);
  if (!feed) {
    return next(new ErrorHandler("Feed not found", 404));
  }

  const comment = {
    user: req.user._id,
    text,
  };

  feed.comments.push(comment);
  await feed.save();

  res.status(201).json({
    success: true,
    message: "Comment added successfully",
    data: feed.comments,
  });
});

// Update Comment 
export const updateComment = catchAsyncErrors(async (req, res, next) => {
  const { commentId, text } = req.body;

  const feed = await CompanyFeed.findById(req.params.id);
  if (!feed) {
    return next(new ErrorHandler("Feed not found", 404));
  }

  const comment = feed.comments.id(commentId);

  if (!comment) {
    return next(new ErrorHandler("Comment not found", 404));
  }

  if (comment.user.toString() !== req.user._id.toString()) {
    return next(new ErrorHandler("You can update only your own comment", 403));
  }

  comment.text = text;
  await feed.save();

  res.status(200).json({
    success: true,
    message: "Comment updated successfully",
    data: feed.comments,
  });
});

// Delete Comment 
export const deleteComment = catchAsyncErrors(async (req, res, next) => {
  const { commentId } = req.body;

  const feed = await CompanyFeed.findById(req.params.id);
  if (!feed) {
    return next(new ErrorHandler("Feed not found", 404));
  }

  const comment = feed.comments.id(commentId);

  if (!comment) {
    return next(new ErrorHandler("Comment not found", 404));
  }

  if (comment.user.toString() !== req.user._id.toString()) {
    return next(new ErrorHandler("You can delete only your own comment", 403));
  }

  feed.comments = feed.comments.filter(
    (c) => c._id.toString() !== commentId.toString()
  );

  await feed.save();

  res.status(200).json({
    success: true,
    message: "Comment deleted successfully",
    data: feed.comments,
  });
});

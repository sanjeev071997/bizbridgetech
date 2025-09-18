import mongoose from "mongoose";
import Advertisement from "../models/advertisementModel.js";
import SellerCategory from "../models/sellercategoriesModel.js";
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";
import cloudinary from "../utils/cloudinary.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";


// Function to handle base64 image uploads
const uploadBase64Image = async (base64Image) => {
  try {
    const result = await cloudinary.uploader.upload(base64Image, {
      folder: "Advertisement",
    });
    return {
      image: result.secure_url,
      cloudinaryId: result.public_id,
    };
  } catch (error) {
    throw new Error("Error uploading base64 image");
  }
};

// Function to add a new advertisement
export const createAdvertisement = catchAsyncErrors(async (req, res, next) => {
  let { offers, image, category } = req.body;

  // Ensure category is always an array
  if (!Array.isArray(category)) {
    category = [category];
  }

  let imageUrl = "";
  let cloudinaryId = "";

  try {
    // Upload Image
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      const result = await cloudinary.uploader.upload(image, {
        folder: "Advertisement",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }

    if (!imageUrl) {
      return next(new Errorhandler("Image upload failed", 400));
    }

    // Save advertisement
    const advertisement = await Advertisement.create({
      user: req.user._id,
      offers,
      image: imageUrl,
      cloudinaryId,
      category, // store as array
    });

    res.status(200).json({
      success: true,
      message: "Advertisement added successfully",
      data: advertisement,
    });
  } catch (error) {
    return next(
      new Errorhandler("Error processing advertisement upload or creation", 500)
    );
  }
});

// Function to get all advertisements
// export const getAllAdvertisements = catchAsyncErrors(async (req, res, next) => {
//   try {
//     let advertisements = await Advertisement.find()
//       .populate("user", "name phone"); 

//     // Populate category manually for only ObjectIds
//     advertisements = await Promise.all(
//       advertisements.map(async (ad) => {
//         const categoryIds = ad.category.filter(c => mongoose.Types.ObjectId.isValid(c));

//         let populatedCategories = [];
//         if (categoryIds.length > 0) {
//           populatedCategories = await SellerCategory.find(
//             { _id: { $in: categoryIds } },
//             "name"
//           );
//         }

//         return {
//           ...ad.toObject(),
//           category: [
//             ...populatedCategories,
//             ...ad.category.filter(c => c === "All") 
//           ]
//         };
//       })
//     );

//     if (advertisements.length === 0) {
//       return next(new Errorhandler("No advertisements found", 404));
//     }

//     res.status(200).json({
//       success: true,
//       data: advertisements,
//     });
//   } catch (error) {
//     return next(new Errorhandler("Error fetching advertisements", 500));
//   }
// });

// Function to get all advertisements
// export const getAllAdvertisements = catchAsyncErrors(async (req, res, next) => {
//   try {
//     // Step 1: Get all ads with user populated
//     let advertisements = await Advertisement.find()
//       .populate("user", "name phone");

//     // Step 2: Get buyer-seller connections for current user
//     const buyerConnections = await BuyerSellerConnection.find({ buyer: req.user._id })
//       .select("seller status");

//     const connectionMap = {};
//     buyerConnections.forEach(conn => {
//       connectionMap[conn.seller.toString()] = conn.status;
//     });

//     // Step 3: Filter advertisements
//     advertisements = advertisements.filter(ad => {
//       const sellerId = ad.user?._id?.toString();
//       if (!sellerId) return false;

//       // If no connection exists -> allow
//       if (!connectionMap[sellerId]) return true;

//       // If connection exists -> allow only when status is "Accepted"
//       return connectionMap[sellerId] === "Accepted";
//     });

//     // Step 4: Populate categories correctly
//     advertisements = await Promise.all(
//       advertisements.map(async (ad) => {
//         const categoryIds = ad.category.filter(c => mongoose.Types.ObjectId.isValid(c));

//         let populatedCategories = [];
//         if (categoryIds.length > 0) {
//           populatedCategories = await SellerCategory.find(
//             { _id: { $in: categoryIds }, user: ad.user._id }, // ensure category belongs to that seller
//             "name"
//           );
//         }

//         // ✅ only categories belonging to seller OR "All"
//         const sellerCategories = populatedCategories.map(c => c.name);

//         const finalCategories = ad.category.filter(c =>
//           c === "All" || sellerCategories.includes(c)
//         );

//         return {
//           ...ad.toObject(),
//           category: finalCategories
//         };
//       })
//     );

//     if (advertisements.length === 0) {
//       return next(new Errorhandler("No advertisements found", 404));
//     }

//     res.status(200).json({
//       success: true,
//       data: advertisements,
//     });
//   } catch (error) {
//     console.error(error);
//     return next(new Errorhandler("Error fetching advertisements", 500));
//   }
// });

// export const getAllAdvertisements = catchAsyncErrors(async (req, res, next) => {
//   try {
//     // Step 1: Get all ads with user populated
//     let advertisements = await Advertisement.find()
//       .populate("user", "name phone");

//     // Step 2: Get buyer-seller connections for current user
//     const buyerConnections = await BuyerSellerConnection.find({ buyer: req.user._id })
//       .select("seller status");

//     const connectionMap = {};
//     buyerConnections.forEach(conn => {
//       connectionMap[conn.seller.toString()] = conn.status;
//     });

//     // Step 3: Filter advertisements
//     advertisements = advertisements.filter(ad => {
//       const sellerId = ad.user?._id?.toString();
//       if (!sellerId) return false;

//       // ❌ Skip self advertisements
//       if (sellerId === req.user._id.toString()) return false;

//       // ❌ Skip if connection exists with status = "Accepted"
//       if (connectionMap[sellerId] === "Accepted") return false;

//       // ✅ If no connection OR connection exists but status != "Accepted" → allow
//       return true;
//     });

//     // Step 4: Filter advertisements by SellerCategory name check
//     advertisements = await Promise.all(
//       advertisements.map(async (ad) => {
//         // Seller ke categories nikalo
//         const sellerCategories = await SellerCategory.find(
//           { user: ad.user._id },
//           "name"
//         );

//         const sellerCategoryNames = sellerCategories.map(c => c.name);

//         // Filter ad.category by matching names
//         const finalCategories = ad.category.filter(c =>
//           c === "All" || sellerCategoryNames.includes(c)
//         );

//         // Agar seller ke paas us ad ki category match nahi hoti → skip ad
//         if (finalCategories.length === 0) return null;

//         return {
//           ...ad.toObject(),
//           category: finalCategories
//         };
//       })
//     );

//     // Null hatao (skip wale ads remove)
//     advertisements = advertisements.filter(ad => ad !== null);

//     if (advertisements.length === 0) {
//       return next(new Errorhandler("No advertisements found", 404));
//     }

//     res.status(200).json({
//       success: true,
//       data: advertisements,
//     });
//   } catch (error) {
//     console.error(error);
//     return next(new Errorhandler("Error fetching advertisements", 500));
//   }
// });


export const getAllAdvertisements = catchAsyncErrors(async (req, res, next) => {
  try {
    // Step 1: Get all ads with user populated
    let advertisements = await Advertisement.find()
      .populate("user", "name phone");

    // Step 2: Get buyer-seller connections for current user
    const buyerConnections = await BuyerSellerConnection.find({ buyer: req.user._id })
      .select("seller status");

    const connectionMap = {};
    buyerConnections.forEach(conn => {
      connectionMap[conn.seller.toString()] = conn.status;
    });

    // Step 3: Filter advertisements
    advertisements = advertisements.filter(ad => {
      const sellerId = ad.user?._id?.toString();
      if (!sellerId) return false;

      // ❌ Skip self advertisements
      if (sellerId === req.user._id.toString()) return false;

      // ❌ Skip if connection exists with status = "Accepted"
      if (connectionMap[sellerId] === "Accepted") return false;

      // ✅ Allow if no connection OR connection not Accepted
      return true;
    });

    // Step 4: Filter advertisements by SellerCategory (id check)
    advertisements = await Promise.all(
      advertisements.map(async (ad) => {
        // Seller ke categories lao
        const sellerCategories = await SellerCategory.find(
          { user: ad.user._id },
          "name"
        );

        const sellerCategoryIds = sellerCategories.map(c => c._id.toString());

        // Debugging log (remove later if not needed)
        console.log("=== DEBUG START ===");
        console.log("Advertisement.category:", ad.category);
        console.log("Seller categories ids:", sellerCategoryIds);
        console.log("Seller categories names:", sellerCategories.map(c => c.name));
        console.log("Connection status:", connectionMap[ad.user._id.toString()]);
        console.log("=== DEBUG END ===");

        // Match categories: only ids or "All"
        const finalCategories = ad.category.filter(c =>
          c.toString() === "All" || sellerCategoryIds.includes(c.toString())
        );

        if (finalCategories.length === 0) return null;

        return {
          ...ad.toObject(),
          category: finalCategories
        };
      })
    );

    // Remove skipped ads
    advertisements = advertisements.filter(ad => ad !== null);

    if (advertisements.length === 0) {
      return next(new Errorhandler("No advertisements found", 404));
    }

    res.status(200).json({
      success: true,
      data: advertisements,
    });
  } catch (error) {
    console.error(error);
    return next(new Errorhandler("Error fetching advertisements", 500));
  }
});



// Function to delete an advertisement
export const deleteAdvertisement = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  // Validate ObjectId
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return next(new Errorhandler("Invalid advertisement ID", 400));
  }

  try {
    const advertisement = await Advertisement.findById(id);
    if (!advertisement) {
      return next(new Errorhandler("Advertisement not found", 404));
    }

    // Delete image from Cloudinary if it exists
    if (advertisement.cloudinaryId) {
      try {
        await cloudinary.uploader.destroy(advertisement.cloudinaryId);
      } catch (cloudError) {
        console.error("Cloudinary delete error:", cloudError);
        return next(new Errorhandler("Error deleting image from Cloudinary", 500));
      }
    }

    // Use deleteOne instead of remove
    await Advertisement.deleteOne({ _id: id });

    res.status(200).json({
      success: true,
      message: "Advertisement deleted successfully",
    });

  } catch (error) {
    console.error("Delete advertisement error:", error);
    return next(new Errorhandler("Error deleting advertisement", 500));
  }
});

// Function to update an advertisement
export const updateAdvertisement = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;
  const { offers, image, category } = req.body;

  try {
    const advertisement = await Advertisement.findById(id);
    if (!advertisement) {
      return next(new Errorhandler("Advertisement not found", 404));
    }
    // Update image if provided
    let imageUrl = advertisement.image;
    let cloudinaryId = advertisement.cloudinaryId;
    if (image && image.startsWith("data:image")) {
      const result = await uploadBase64Image(image);
      imageUrl = result.image;
      cloudinaryId = result.cloudinaryId;
    } else if (image) {
      const result = await cloudinary.uploader.upload(image, {
        folder: "Advertisement",
      });
      imageUrl = result.secure_url;
      cloudinaryId = result.public_id;
    }
    advertisement.offers = offers || advertisement.offers;
    advertisement.image = imageUrl;
    advertisement.cloudinaryId = cloudinaryId;
    advertisement.category = category || advertisement.category;
    await advertisement.save();
    res.status(200).json({
      success: true,
      message: "Advertisement updated successfully",
      data: advertisement,
    });
  } catch (error) {
    return next(new Errorhandler("Error updating advertisement", 500));
  }
});

// Function to get an advertisement by ID
export const getAdvertisementById = catchAsyncErrors(async (req, res, next) => {
  const { id } = req.params;

  try {
    let advertisement = await Advertisement.findById(id)
      .populate("user", "name email"); 

    if (!advertisement) {
      return next(new Errorhandler("Advertisement not found", 404));
    }

    // Manually populate category names for ObjectIds
    const categoryIds = advertisement.category.filter(c => mongoose.Types.ObjectId.isValid(c));

    let populatedCategories = [];
    if (categoryIds.length > 0) {
      populatedCategories = await SellerCategory.find(
        { _id: { $in: categoryIds } },
        "name"
      );
    }

    advertisement = {
      ...advertisement.toObject(),
      category: [
        ...populatedCategories,
        ...advertisement.category.filter(c => c === "All")
      ]
    };

    res.status(200).json({
      success: true,
      data: advertisement,
    });
  } catch (error) {
    return next(new Errorhandler("Error fetching advertisement", 500));
  }
});

// Function to get advertisements by category
export const getAdvertisementsByCategory = catchAsyncErrors(async (req, res, next) => {
  const { categoryId } = req.params;

  try {
    const ads = await Advertisement.find({
      $or: [
        { category: categoryId }, // Matches specific category
        { category: "All" }       // Matches All categories
      ]
    });

    res.status(200).json({
      success: true,
      data: ads,
    });
  } catch (error) {
    return next(new Errorhandler("Error fetching advertisements", 500));
  }
});

// Function to get advertisements by user ID
export const getAdvertisementsByUserId = catchAsyncErrors(async (req, res, next) => {
  const { userId } = req.params;
  try {
    let advertisements = await Advertisement.find({ user: userId })
      .populate({
        path: "user",
        select: "name phone"
      });

    // Populate only ObjectId categories manually
    advertisements = await Promise.all(
      advertisements.map(async (ad) => {
        const categoryIds = ad.category.filter(c => mongoose.Types.ObjectId.isValid(c));

        if (categoryIds.length > 0) {
          const populatedCategories = await mongoose.model("SellerCategory").find(
            { _id: { $in: categoryIds } },
            "name"
          );

          return {
            ...ad.toObject(),
            category: [
              ...populatedCategories,
              ...ad.category.filter(c => c === "All") 
            ]
          };
        }

        return ad.toObject();
      })
    );

    if (!advertisements.length) {
      return next(new Errorhandler("No advertisements found for this user", 404));
    }

    res.status(200).json({
      success: true,
      data: advertisements,
    });
  } catch (error) {
    console.error("Error fetching advertisements:", error);
    return next(new Errorhandler("Error fetching advertisements by user ID", 500));
  }
});

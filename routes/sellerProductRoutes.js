import express from "express";
import multer from 'multer';
import {
  addProduct,
  updateProductCategoryAndVisibility,
  updateProduct,
  deleteProduct,
  getProductByUserId,
  getAllProducts,
  getBuyerProducts,
  getProductsByBuyerCategoryId,
  getProductsByConnection,
  toggleProductsVisibilityByBuyerCategory,
  // getProductsByCategoryId,
  // getProductById,
  applyGlobalDiscount,
  sellerProducts,
} from "../controllers/sellerProductController.js";
import { isAuthenticatedUser, isAdmin } from "../middlewares/authMiddleware.js";

// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage }); 

const router = express.Router();

router.post("/", upload.single('image'), isAuthenticatedUser, addProduct); 

router.put("/update-buyer-category-visibility", isAuthenticatedUser, updateProductCategoryAndVisibility); // seller dashboard ye api product k buyer category and visibility update krne k liye h

router.put("/:id", upload.single('image'), isAuthenticatedUser, updateProduct);

router.delete("/:id", isAuthenticatedUser, deleteProduct);

router.get("/get/user/product", isAuthenticatedUser, getProductByUserId); //seller k apne product hoge   // seller can see their own products

router.get("/get/buyer/products", isAuthenticatedUser, getBuyerProducts); // buyer dashboard me ye apis call hoge // buyer can see products assigned to them

router.get("/get/:buyerCategory", isAuthenticatedUser, getProductsByBuyerCategoryId); // seller dashbaord me buyerCategory k onclick pr data is se aagye    // buyer can see products assigned to their category 

router.post("/get/products-by-connection", isAuthenticatedUser, getProductsByConnection); // new route to get products by connection 

router.post("/hide-products-by-buyer-category", isAuthenticatedUser, toggleProductsVisibilityByBuyerCategory);

router.post("/apply-global-discount", isAuthenticatedUser, applyGlobalDiscount)
// Admin routes
router.get("/", isAuthenticatedUser, isAdmin, getAllProducts);  // admin can see all products

// router.get("/:category", isAuthenticatedUser, getProductsByCategoryId);

// router.get("/get/product/:id", isAuthenticatedUser, getProductById);


// Get Sellers Products for a Buyer New Apis -> (Buyer Only)
router.post("/all", isAuthenticatedUser, sellerProducts);

export default router;
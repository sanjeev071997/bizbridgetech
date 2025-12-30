import express from 'express';
import {
  createBuyerCategory, 
  getAllBuyerCategories,
  getBuyerCategoryById,
  updateBuyerCategory,
  deleteBuyerCategory,
  adminGetAllBuyerCategories,
} from '../controllers/buyerCategoryController.js';
import { isAuthenticatedUser, isAdmin} from "../middlewares/authMiddleware.js";
const router = express.Router();

router.post('/', isAuthenticatedUser, createBuyerCategory);
router.get('/', isAuthenticatedUser, getAllBuyerCategories);  
router.get('/:id', isAuthenticatedUser, getBuyerCategoryById);
router.put('/:id', isAuthenticatedUser, updateBuyerCategory);
router.delete('/:id', isAuthenticatedUser, deleteBuyerCategory);


// Admin route to get all Buyer categories
router.get('/admin/get', isAuthenticatedUser, isAdmin, adminGetAllBuyerCategories);

export default router;

import express from "express";
import multer from 'multer';
import {
  createFeed,
  getAllFeeds,
  getFeedById,
  updateFeed,
  deleteFeed,
  likeFeed,
  unlikeFeed,
  addComment,
  updateComment,
  deleteComment,
} from "../controllers/companyfeedsController.js";
import { isAuthenticatedUser } from "../middlewares/authMiddleware.js";
// Configure Multer for file uploads
const storage = multer.diskStorage({});
const upload = multer({ storage });

const router = express.Router();

router.post("/", isAuthenticatedUser, upload.single('image'), createFeed);
router.get("/", isAuthenticatedUser, getAllFeeds);
router.get("/:id", isAuthenticatedUser, getFeedById);
router.put("/:id", isAuthenticatedUser, upload.single('image'), updateFeed);
router.delete("/:id/delete", isAuthenticatedUser, deleteFeed);

router.put("/:id/like", isAuthenticatedUser, likeFeed);
router.put("/:id/unlike", isAuthenticatedUser, unlikeFeed);

router.post("/:id/comment", isAuthenticatedUser, addComment);
router.put("/:id/comment", isAuthenticatedUser, updateComment);
router.delete("/:id/comment", isAuthenticatedUser, deleteComment);

export default router;

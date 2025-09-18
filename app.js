import express from "express";
import dotenv from "dotenv";
import http from "http";
import { Server } from "socket.io";
import dbConfig from "./config/dbConfig.js";
import cors from "cors";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import errorMiddleware from "./middlewares/error.js";
import authRoute from "./routes/authRoute.js";
import contactRoute from "./routes/contactRoutes.js";
import sellerCategoryRoutes from "./routes/sellerCategoryRoutes.js";
import sellerProductRoutes from "./routes/sellerProductRoutes.js";
import buyerCategoryRoutes from "./routes/buyerCategoryRoutes.js";
import testimonialRoutes from "./routes/testimonialRoutes.js";
import advertisementRoutes from "./routes/advertisementRoutes.js";
import PaymentOption from "./routes/paymentOptionRoutes.js";
import SchemeRoutes from "./routes/schemeRoutes.js";
import supportRoutes from "./routes/supportRoutes.js";
import buyerSellerConnectionRoutes from "./routes/buyerSellerConnectionRoutes.js";
import chatRoutes from "./routes/chatRoutes.js";
import cartRoutes from "./routes/cartRoutes.js";
import orderRoutes from "./routes/orderRoutes.js";
import companyFeedRoutes from "./routes/companyfeedsRoutes.js";
import invoiceRoutes from "./routes/invoiceRoutes.js";
import brandsRoutes from "./routes/brandsRoutes.js";
import { startInterestCron } from "./utils/invoiceInterestCron.js";

import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const port = process.env.PORT || 8080;

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true 
}));
app.options('*', cors()); 
app.use(bodyParser.json());
app.use(cookieParser());

// Create HTTP server and attach Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    credentials: true 
  },
});

// Attach io to every request
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Check Server Status
app.get("/api/status", (req, res) => {
  res.json({ data: true, message: "Server is running" });
});

// APIs end points
app.use("/api/v1/auth", authRoute);
app.use("/api/v1/contact", contactRoute);
app.use("/api/v1/seller-categories", sellerCategoryRoutes);
app.use("/api/v1/seller-products", sellerProductRoutes);
app.use("/api/v1/buyer-categories", buyerCategoryRoutes);
app.use("/api/v1/testimonial", testimonialRoutes);
app.use("/api/v1/advertisement", advertisementRoutes);
app.use("/api/v1/payment-options", PaymentOption);
app.use("/api/v1/schemes", SchemeRoutes);
app.use("/api/v1/support", supportRoutes);
app.use("/api/v1/buyer-seller-connections", buyerSellerConnectionRoutes);
app.use("/api/v1/chat", chatRoutes);
app.use("/api/v1/cart", cartRoutes);
app.use("/api/v1/order", orderRoutes);
app.use("/api/v1/company/feed", companyFeedRoutes);
app.use("/api/v1/invoices", invoiceRoutes);
app.use("/api/v1/brands", brandsRoutes);

// Static files
app.use(express.static(path.join(__dirname, "./build")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "./build/index.html"));
});

// Error middleware
app.use(errorMiddleware);

// socket connection
io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  // join room based on connectionId
  socket.on("joinRoom", (connectionId) => {
    socket.join(connectionId);
    console.log(`User joined room: ${connectionId}`);
  });

  // send message
  socket.on("sendMessage", async (data) => {
    const newMsg = new ChatMessage(data);
    await newMsg.save();

    // emit to receiver in same room
    io.to(data.connectionId).emit("receiveMessage", newMsg);
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

  startInterestCron();     // daily per-day interest

// Start server with Socket.IO attached
server.listen(port, () => {
  console.log(`App listening on port ${port}`);
});

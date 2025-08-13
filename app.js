import express from "express";
import dotenv from "dotenv";
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

import path from "path";
import { fileURLToPath } from "url";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const port = process.env.PORT || 8080;

const app = express();
// app.use(express.json());
dotenv.config();
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
// app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser());

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

// Static files
app.use(express.static(path.join(__dirname, "./build")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "./build/index.html"));
});

// Middleware for errors
app.use(errorMiddleware);

function startServer() {
  const server = app.listen(port, () => {
    console.log(`App listening on port ${port}`);
  });

}

startServer();

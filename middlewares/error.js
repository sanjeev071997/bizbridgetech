import Errorhandler from "../utils/Errorhandler.js";

export default (error, req, res, next) => {
    error.statusCode = error.statusCode || 500;
    error.message = error.message || "Internal Server Error";
    
    // Wrong Mongodb Id error
    if (error.name === "CastError") {
        const message = `Resource not found. Invalid: ${error.path}`;
        error = new Errorhandler(message, 400);
    }

    // Mongoose duplicate key error
    if (error.code === 11000) {
        const message = `Duplicate ${Object.keys(error.keyValue)} Entered`;
        error = new Errorhandler(message, 400);
    }

    // Wrong JWT Error
    if (error.name === "JsonWebTokenError") {
        const message =  `Json Web Token is invalid, Try again`;
        error = new Errorhandler(message, 400);
    }

    // JWT Expire Error
    if (error.name === "TokenExpiredError") {
        const message =  `Json Web Token is Expired, Try again`;
        error = new Errorhandler(message, 400);
    }

    res.status(error.statusCode).json({
        success: false,
        message: error.message,
        // error:error.stack, 
    });
};



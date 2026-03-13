import mongoose from "mongoose";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";
import User from "../models/userModel.js";
import Plan from "../models/planModel.js";
import Bill from "../models/billModel.js"
import Errorhandler from "../utils/Errorhandler.js";
import catchAsyncErrors from "../middlewares/catchAsyncErrors.js";

// Seller Billing - Get Buyers List with Bill Generation
export const getSellerBilling = catchAsyncErrors(async (req, res, next) => {
  try {
    const userId = req.user._id;
    const mode = req.user.mode;

    // Sirf seller ke liye allow karo
    if (mode !== "seller") {
      return next(new Errorhandler("Only sellers can access billing", 403));
    }

    console.log("Current User ID:", userId.toString());

    // Seller ka plan check karo
    const plan = await Plan.findById(req.user.planId);
    if (!plan) {
      return next(new Errorhandler("Plan not found", 404));
    }

    console.log("Plan:", plan.name);
    console.log("Base Price (Fixed):", plan.billingOptions?.monthly?.price);
    console.log("Dealer Price (Per Buyer):", plan.dealerPrice);

    // Plan active hai aur custom plan nahi hai
    if (!plan.isActive || plan.customPlan) {
      return next(new Errorhandler("Invalid plan for billing", 400));
    }

    // Current date for billing
    const currentDate = new Date();
    const currentMonth = currentDate.getMonth();
    const currentYear = currentDate.getFullYear();

    // FIXED: Billing Date seller ke createdAt ke hisaab se
    const sellerCreatedDate = new Date(req.user.createdAt);
    const billingDate = new Date(
      currentYear, 
      currentMonth, 
      sellerCreatedDate.getDate(),
      sellerCreatedDate.getHours(),
      sellerCreatedDate.getMinutes(),
      sellerCreatedDate.getSeconds()
    );
    
    // FIXED: Due Date - billingDate se 3 din baad
    const dueDate = new Date(billingDate);
    dueDate.setDate(dueDate.getDate() + 3);

    console.log("Billing Date:", billingDate);
    console.log("Due Date:", dueDate);

    // Seller ke saare active connections fetch karo
    const connections = await BuyerSellerConnection.find({
      seller: userId,
      status: "Accepted"
    })
    .populate({
      path: "buyer",
      select: "name phone phoneVerified businessName email lastSeen profileImage createdAt mode"
    })
    .populate("buyerCategory", "name discount")
    .lean();

    console.log("Total connections found:", connections.length);

    if (connections.length === 0) {
      return res.status(200).json({
        success: true,
        message: "No connections found for this seller",
        summary: {
          totalBuyers: 0,
          verifiedBuyers: 0,
          unverifiedBuyers: 0,
          hasBill: false,
          billingDate: billingDate,
          dueDate: dueDate,
          amounts: {
            totalBillingAmount: 0,
            totalPaidAmount: 0,
            pendingAmount: 0
          },
          currentMonth: currentMonth + 1,
          currentYear: currentYear
        }
      });
    }

    // Buyers ko categorize karo (verified vs unverified)
    const verifiedBuyersList = [];
    const unverifiedBuyersList = [];
    
    let verifiedBuyersCount = 0;
    let totalDealerPrice = 0;

    // Har buyer ke liye calculation
    for (const conn of connections) {
      const isVerified = conn.buyer 
        ? conn.buyer.phoneVerified === true 
        : conn.phoneVerified === true;

      const dealerPricePerBuyer = plan.dealerPrice || 0;
      
      // Category discount sirf dealerPrice par apply hoga
      let discount = 0;
      let finalDealerPrice = dealerPricePerBuyer;

      if (conn.buyerCategory && conn.buyerCategory.discount) {
        discount = (dealerPricePerBuyer * conn.buyerCategory.discount) / 100;
        finalDealerPrice = dealerPricePerBuyer - discount;
      }

      if (isVerified) {
        verifiedBuyersCount++;
        totalDealerPrice += finalDealerPrice;
      } else {
        let reason = "";
        if (!conn.buyer) {
          reason = "Unregistered dealers - phone verification pending";
        } else if (!conn.buyer.phoneVerified) {
          reason = "Unregistered Dealers"; // Phone number not verified 
        } else {
          reason = "Dealers not verified";
        }
        
        unverifiedBuyersList.push({
          phone: conn.buyer?.phone || conn.buyerPhone,
          name: conn.buyer?.name || null,
          businessName: conn.buyer?.businessName || null,
          isRegistered: !!conn.buyer,
          reason: reason,
          phoneVerified: isVerified
        });
      }
    }

    // FIXED: Total Amount Calculation
    // Total = basePrice (fixed) + (dealerPrice × total verified buyers)
    const basePrice = plan.billingOptions?.monthly?.price || 0;
    const totalBillingAmount = basePrice + totalDealerPrice;

    console.log("Calculation:", {
      basePrice,
      verifiedBuyersCount,
      totalDealerPrice,
      totalBillingAmount
    });

    // Check if bill already exists for this seller this month
    let sellerBill = await Bill.findOne({
      sellerId: userId,
      month: currentMonth,
      year: currentYear
    });

    const isNewBill = !sellerBill;

    // Agar bill exist nahi karta to create karo
    if (!sellerBill && verifiedBuyersCount > 0) {
      // Agar current date billing date se bada ya equal hai to bill generate karo
      if (currentDate >= billingDate) {
        // Create consolidated bill - WITHOUT items array
        sellerBill = await Bill.create({
          sellerId: userId,
          unverifiedBuyers:unverifiedBuyersList.length,
          verifiedBuyers:verifiedBuyersCount,
          totalDealers:connections.length,
          month: currentMonth,
          year: currentYear,
          billingDate: billingDate,
          dueDate: dueDate,
          summary: {
            totalBuyers: verifiedBuyersCount,
            basePrice: basePrice,
            totalDealerPrice: totalDealerPrice,
            totalAmount: totalBillingAmount
          },
          status: 'pending'
        });

        console.log("New consolidated bill created:", sellerBill._id);
      }
    }

    // Calculate paid bills amount (historical)
    const paidBills = await Bill.find({
      sellerId: userId,
      status: 'paid'
    });

    const totalPaidAmount = paidBills.reduce((sum, bill) => sum + bill.summary.totalAmount, 0);

    // Response send karo - WITHOUT items details
    res.status(200).json({
      success: true,
      summary: {
        totalBuyers: connections.length,
        verifiedBuyers: verifiedBuyersCount,
        unverifiedBuyers: unverifiedBuyersList.length,
        hasBill: !!sellerBill,
        isNewBill: isNewBill && !!sellerBill,
        billId: sellerBill?._id,
        billStatus: sellerBill?.status || 'no_bill',
        billingDate: billingDate,
        dueDate: dueDate,
        calculation: {
          basePrice: basePrice,
          dealerPricePerBuyer: plan.dealerPrice || 0,
          verifiedBuyersCount,
          totalDealerPrice,
          totalBillingAmount
        },
        amounts: {
          totalBillingAmount,
          totalPaidAmount,
          pendingAmount: totalBillingAmount - totalPaidAmount
        },
        currentMonth: currentMonth + 1,
        currentYear: currentYear,
        sellerSince: req.user.createdAt
      },
      verifiedBuyers: verifiedBuyersCount, // Sirf count
      unverifiedBuyers: unverifiedBuyersList.map(b => ({
        phone: b.phone,
        name: b.name,
        businessName: b.businessName,
        reason: b.reason
      }))
    });

  } catch (error) {
    console.error("Error in getSellerBilling:", error);
    return next(new Errorhandler(error.message, 500));
  }
});

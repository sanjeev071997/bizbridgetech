// cron/billingCron.js
import cron from "node-cron";
import SystemLog from "../models/SystemLog.js";
import Bill from "../models/billModel.js";
import User from "../models/userModel.js";
import Plan from "../models/planModel.js";
import BuyerSellerConnection from "../models/buyerSellerConnectionModels.js";

const getISTDate = () =>
  new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Kolkata" }));

const getMonthKey = (date) =>
  `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;

// Billing calculation function
const calculateSellerBilling = async (seller, currentDate, monthKey) => {
  try {
    const currentMonth = currentDate.getMonth();
    const currentYear = currentDate.getFullYear();

    // Check if bill already exists for this seller this month
    const existingBill = await Bill.findOne({
      sellerId: seller._id,
      month: currentMonth,
      year: currentYear
    });

    if (existingBill) {
      return { success: false, message: "Bill already exists", existingBill };
    }

    // Seller ka plan check karo
    const plan = await Plan.findById(seller.planId);
    if (!plan || !plan.isActive || plan.customPlan) {
      return { success: false, message: "Invalid plan" };
    }

    // Seller ke connections fetch karo
    const connections = await BuyerSellerConnection.find({
      seller: seller._id,
      status: "Accepted"
    }).populate('buyer').populate('buyerCategory');

    if (connections.length === 0) {
      return { success: false, message: "No connections found" };
    }

    // Verified buyers count karo
    let verifiedBuyersCount = 0;
    let totalDealerPrice = 0;

    for (const conn of connections) {
      const isVerified = conn.buyer 
        ? conn.buyer.phoneVerified === true 
        : conn.phoneVerified === true;

      if (isVerified) {
        verifiedBuyersCount++;
        
        // Discount calculation agar category ho to
        let dealerPrice = plan.dealerPrice || 0;
        if (conn.buyerCategory && conn.buyerCategory.discount) {
          const discount = (dealerPrice * conn.buyerCategory.discount) / 100;
          dealerPrice = dealerPrice - discount;
        }
        
        totalDealerPrice += dealerPrice;
      }
    }

    if (verifiedBuyersCount === 0) {
      return { success: false, message: "No verified buyers" };
    }

    // Calculate billing date based on seller's createdAt
    const sellerCreatedDate = new Date(seller.createdAt);
    const billingDate = new Date(
      currentYear, 
      currentMonth, 
      sellerCreatedDate.getDate(),
      sellerCreatedDate.getHours(),
      sellerCreatedDate.getMinutes(),
      sellerCreatedDate.getSeconds()
    );

    const dueDate = new Date(billingDate);
    dueDate.setDate(dueDate.getDate() + 3);

    const basePrice = plan.billingOptions?.monthly?.price || 0;
    const totalBillingAmount = basePrice + totalDealerPrice;

    // Create bill
    const bill = await Bill.create({
      sellerId: seller._id,
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

    return { 
      success: true, 
      message: "Bill created successfully", 
      bill,
      details: {
        sellerId: seller._id,
        verifiedBuyers: verifiedBuyersCount,
        amount: totalBillingAmount
      }
    };

  } catch (error) {
    console.error(`Error calculating billing for seller ${seller._id}:`, error);
    return { success: false, message: error.message };
  }
};

// Main billing cron function
export const runMonthlyBilling = async (runDate) => {
  console.log(`\n💰 Running Monthly Billing for date: ${runDate.toString()}`);
  
  try {
    const currentMonth = runDate.getMonth();
    const currentYear = runDate.getFullYear();
    const monthKey = getMonthKey(runDate);

    // Saare active sellers fetch karo
    const sellers = await User.find({ 
      mode: 'seller', 
      isActive: true,
      planId: { $ne: null }
    });

    console.log(`📊 Total active sellers found: ${sellers.length}`);

    const results = {
      total: sellers.length,
      processed: 0,
      skipped: 0,
      failed: 0,
      bills: []
    };

    for (const seller of sellers) {
      try {
        const result = await calculateSellerBilling(seller, runDate, monthKey);
        
        if (result.success) {
          results.processed++;
          results.bills.push(result.details);
          console.log(`✅ Bill created for seller ${seller._id}: ₹${result.details.amount}`);
        } else {
          results.skipped++;
          console.log(`⏭️ Skipped seller ${seller._id}: ${result.message}`);
        }
      } catch (error) {
        results.failed++;
        console.error(`❌ Failed for seller ${seller._id}:`, error.message);
      }
    }

    // Log the run in SystemLog
    await SystemLog.findOneAndUpdate(
      { key: "monthlyBilling" },
      { 
        value: monthKey, 
        lastRun: new Date(),
        details: results
      },
      { upsert: true }
    );

    console.log(`📈 Billing Summary:`, {
      total: results.total,
      processed: results.processed,
      skipped: results.skipped,
      failed: results.failed,
      totalAmount: results.bills.reduce((sum, b) => sum + b.amount, 0)
    });

    return results;

  } catch (error) {
    console.error("❌ Error in runMonthlyBilling:", error);
    throw error;
  }
};

// Start all cron jobs
export const startBillingCron = () => {
  console.log("🚀 Starting Monthly Billing Cron...");
  console.log("Current IST Time:", getISTDate().toString());

  // TEST CRON - हर 5 मिनट में (सिर्फ testing के लिए)
  cron.schedule(
    "*/5 * * * *",
    async () => {
      const istNow = getISTDate();
      console.log(`\n🔍 TEST RUN at ${istNow.toString()}`);
      
      // Check if it's billing day (seller ke createdAt ke hisaab se)
      // Testing के लिए हम सिर्फ log करेंगे, actual billing नहीं करेंगे
      console.log(`📅 Testing mode - No actual billing will run`);
    },
    { timezone: "Asia/Kolkata" }
  );

  // MAIN BILLING CRON - हर दिन 23:59 बजे
  cron.schedule(
    "59 23 * * *",
    async () => {
      const istNow = getISTDate();
      console.log(`\n🎯 MAIN BILLING CRON triggered at ${istNow.toString()}`);

      const monthKey = getMonthKey(istNow);
      console.log(`📅 Month key: ${monthKey}`);

      // Check if already run today
      const alreadyRun = await SystemLog.findOne({ key: "monthlyBilling" });
      console.log(`📝 Previous run record:`, alreadyRun);

      // Agar aaj already run ho chuka hai to skip karo
      if (alreadyRun?.lastRun) {
        const lastRunDate = new Date(alreadyRun.lastRun);
        if (lastRunDate.toDateString() === istNow.toDateString()) {
          console.log("⏭️ Billing already run today, skipping...");
          return;
        }
      }

      console.log("🎯 Running monthly billing for:", monthKey);
      const result = await runMonthlyBilling(istNow);

      console.log("✅ Monthly billing completed. Result:", result);
    },
    { timezone: "Asia/Kolkata" }
  );

  // RECOVERY CHECK - हर दिन 00:05 बजे (अगले दिन)
  cron.schedule(
    "5 0 * * *",
    async () => {
      const istNow = getISTDate();
      console.log(`\n🔍 BILLING RECOVERY CHECK at ${istNow.toString()}`);

      // Check if billing ran yesterday
      const yesterday = new Date(istNow);
      yesterday.setDate(yesterday.getDate() - 1);
      const yesterdayMonthKey = getMonthKey(yesterday);

      const alreadyRun = await SystemLog.findOne({ key: "monthlyBilling" });
      console.log(`📝 Previous run record:`, alreadyRun);

      // अगर कल billing नहीं चली तो
      if (!alreadyRun || alreadyRun.value !== yesterdayMonthKey) {
        console.log("🚨 Missed billing detected! Running recovery for:", yesterdayMonthKey);
        
        const result = await runMonthlyBilling(yesterday);

        await SystemLog.findOneAndUpdate(
          { key: "monthlyBilling" },
          { 
            value: yesterdayMonthKey, 
            lastRun: new Date(),
            recovered: true,
            details: result
          },
          { upsert: true }
        );

        console.log("✅ Recovery execution completed for", yesterdayMonthKey);
      } else {
        console.log("⏭️ Recovery skipped - billing already executed for", yesterdayMonthKey);
      }
    },
    { timezone: "Asia/Kolkata" }
  );

  // MANUAL TRIGGER API के लिए endpoint (optional)
  console.log("✅ Monthly Billing Cron Registered Successfully");
  console.log("   - Test: Every 5 minutes");
  console.log("   - Main: Daily 23:59");
  console.log("   - Recovery: Daily 00:05\n");
};

// Manual trigger function (API se call karne ke liye)
export const triggerManualBilling = async (req, res) => {
  try {
    const istNow = getISTDate();
    console.log("🔧 Manual billing triggered at:", istNow.toString());

    const result = await runMonthlyBilling(istNow);

    res.status(200).json({
      success: true,
      message: "Manual billing completed",
      data: result
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
};
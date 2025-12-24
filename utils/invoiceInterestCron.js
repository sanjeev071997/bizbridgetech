import cron from "node-cron";
import { runMonthlyInterestForAll } from "../controllers/invoiceController.js";
import { isLastDayOfMonth } from "../utils/InvoiceTime.js";

console.log("📌 invoiceInterestCron file loaded");

export const startInterestCron = () => {
  console.log("⏰ startInterestCron initialized");

  
// Run at 11:59 PM on 28th-31st of every month
cron.schedule('59 23 28-31 * *', async () => {
  const now = new Date();
  if (isLastDayOfMonth(now)) {
    console.log(`Running monthly interest on ${now.toISOString()}...`);
    await runMonthlyInterestForAll(now);
  }
});
};

// cron.schedule(
  //   "59 23 * * *", // "11:59 PM every day"
  //   //  "*/1 * * * *",  // every minute for testing
  //   async () => {
  //     try {
  //       console.log("[CRON] Daily interest job start");
  //       await runDailyInterestForAll(new Date());
  //       console.log("[CRON] Daily interest job done");
  //     } catch (err) {
  //       console.error("[CRON] Daily interest job error:", err);
  //     }
  //   },
  //   { timezone: "Asia/Kolkata" }
  // );

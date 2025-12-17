import cron from "node-cron";
import { runDailyInterestForAll } from "../controllers/invoiceController.js";

console.log("📌 invoiceInterestCron file loaded");

export const startInterestCron = () => {
  console.log("⏰ startInterestCron initialized");

  cron.schedule(
    "59 23 * * *", // "11:59 PM every day"
    //  "*/1 * * * *",  // every minute for testing
    async () => {
      try {
        console.log("[CRON] Daily interest job start");
        await runDailyInterestForAll(new Date());
        console.log("[CRON] Daily interest job done");
      } catch (err) {
        console.error("[CRON] Daily interest job error:", err);
      }
    },
    { timezone: "Asia/Kolkata" }
  );
};


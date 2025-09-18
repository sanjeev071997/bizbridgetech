import cron from "node-cron";
import { runDailyInterestForAll } from "../controllers/invoiceController.js";

export const startInterestCron = () => {
  cron.schedule("5 1 * * *", async () => {
    try {
      console.log("[CRON] Daily interest job start");
      await runDailyInterestForAll(new Date());
      console.log("[CRON] Daily interest job done");
    } catch (err) {
      console.error("[CRON] Daily interest job error:", err);
    }
  }, { timezone: "Asia/Kolkata" });
};

import cron from "node-cron";
import SystemLog from "../models/SystemLog.js";
import { runMonthlyInterestForAll } from "../controllers/invoiceController.js";

const getISTDate = () =>
  new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Kolkata" }));

const getMonthKey = (date) =>
  `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;

export const startInterestCron = () => {
  console.log("🚀 Starting Monthly Interest Cron...");
  console.log("Current IST Time:", getISTDate().toString());

  // TEST CRON - हर 5 मिनट में चलेगा (सिर्फ testing के लिए)
  cron.schedule(
    "*/5 * * * *",
    async () => {
      const istNow = getISTDate();
      console.log(`\n🔍 TEST RUN at ${istNow.toString()}`);
      console.log(`📅 Date components:`, {
        year: istNow.getFullYear(),
        month: istNow.getMonth() + 1,
        date: istNow.getDate(),
        day: istNow.getDay()
      });
      
      // Check if it's 1st of month या last day
      const tomorrow = new Date(istNow);
      tomorrow.setDate(tomorrow.getDate() + 1);
      
      const isLastDay = tomorrow.getDate() === 1;
      const isFirstDay = istNow.getDate() === 1;
      
      if (isLastDay || isFirstDay) {
        console.log(`🎯 ${isLastDay ? 'Last day' : 'First day'} of month detected, running interest...`);
        console.log(`📅 Running for date: ${istNow.toLocaleDateString()}`);
        
        await runMonthlyInterestForAll(istNow);
      } else {
        console.log(`⏭️ Not month end/start (today: ${istNow.getDate()}, tomorrow: ${tomorrow.getDate()})`);
      }
    },
    { timezone: "Asia/Kolkata" }
  );

  // MAIN CRON - हर दिन 23:59 बजे
  cron.schedule(
    "59 23 * * *",
    async () => {
      const istNow = getISTDate();
      console.log(`\n🎯 MAIN CRON triggered at ${istNow.toString()}`);

      // Check if today is last day of month
      const tomorrow = new Date(istNow);
      tomorrow.setDate(tomorrow.getDate() + 1);
      
      const isLastDayOfMonth = tomorrow.getDate() === 1;
      
      if (isLastDayOfMonth) {
        console.log("📅 Today is last day of month, running interest...");
        
        const monthKey = getMonthKey(istNow);
        console.log(`📅 Month key: ${monthKey}`);

        const alreadyRun = await SystemLog.findOne({ key: "monthlyInterest" });
        console.log(`📝 Previous run record:`, alreadyRun);

        if (alreadyRun?.value === monthKey) {
          console.log("⏭️ Interest already run for this month according to SystemLog");
        } else {
          console.log("🎯 Running month-end interest for:", monthKey);
          const result = await runMonthlyInterestForAll(istNow);

          await SystemLog.findOneAndUpdate(
            { key: "monthlyInterest" },
            { value: monthKey, lastRun: new Date() },
            { upsert: true }
          );

          console.log("✅ Monthly interest completed. Result:", result);
        }
      } else {
        console.log(`⏭️ Not last day of month (today: ${istNow.getDate()}, tomorrow: ${tomorrow.getDate()})`);
      }
    },
    { timezone: "Asia/Kolkata" }
  );

  // RECOVERY CHECK - हर दिन 00:05 बजे
  cron.schedule(
    "5 0 * * *",
    async () => {
      const istNow = getISTDate();
      console.log(`\n🔍 RECOVERY CHECK at ${istNow.toString()}`);

      // अगर आज 1 तारीख है
      if (istNow.getDate() === 1) {
        console.log("📅 1st of month detected - checking for missed interest...");
        
        // पिछले महीने के लिए monthKey बनाओ
        const prevMonth = new Date(istNow);
        prevMonth.setMonth(prevMonth.getMonth() - 1);
        const monthKey = getMonthKey(prevMonth);

        const alreadyRun = await SystemLog.findOne({ key: "monthlyInterest" });
        console.log(`📝 Previous run record for ${monthKey}:`, alreadyRun);

        if (alreadyRun?.value === monthKey) {
          console.log("⏭️ Recovery skipped - interest already executed for", monthKey);
        } else {
          console.log("🚨 Missed interest detected! Running recovery for:", monthKey);
          
          // पिछले महीने के आखिरी दिन की date बनाओ
          const lastDayOfPrevMonth = new Date(
            prevMonth.getFullYear(),
            prevMonth.getMonth() + 1,
            0,
            23,
            59,
            0
          );

          console.log(`📅 Running recovery for date: ${lastDayOfPrevMonth.toLocaleDateString()}`);
          const result = await runMonthlyInterestForAll(lastDayOfPrevMonth);

          await SystemLog.findOneAndUpdate(
            { key: "monthlyInterest" },
            { value: monthKey, lastRun: new Date(), recovered: true },
            { upsert: true }
          );

          console.log("✅ Recovery execution completed for", monthKey, "Result:", result);
        }
      } else {
        console.log(`⏭️ Not 1st of month (today is ${istNow.getDate()})`);
      }
    },
    { timezone: "Asia/Kolkata" }
  );

  console.log("✅ Monthly Interest Cron Registered Successfully");
  console.log("   - Test: Every 5 minutes");
  console.log("   - Main: Daily 23:59 (only on last day)");
  console.log("   - Recovery: Daily 00:05 (only on 1st)\n");
};


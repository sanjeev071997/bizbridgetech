// import cron from "node-cron";
// import { runMonthlyInterestForAll } from "../controllers/invoiceController.js";
// import { isLastDayOfMonth } from "../utils/InvoiceTime.js";

// console.log("📌 invoiceInterestCron file loaded");

// export const startInterestCron = () => {
//   console.log("⏰ startInterestCron initialized");

  
// // Run at 11:59 PM on 28th-31st of every month
// cron.schedule('59 23 28-31 * *', async () => {
//   const now = new Date();
//   if (isLastDayOfMonth(now)) {
//     console.log(`Running monthly interest on ${now.toISOString()}...`);
//     await runMonthlyInterestForAll(now);
//   }
// });
// };

// cronJobs/invoiceInterestCron.js
// import cron from "node-cron";
// import mongoose from "mongoose";
// import { runMonthlyInterestForAll } from "../controllers/invoiceController.js";
// import { isLastDayOfMonth } from "../utils/InvoiceTime.js";

// console.log("📌 invoiceInterestCron file loaded - " + new Date().toISOString());

// // cronJobs/invoiceInterestCron.js में
// export const startInterestCron = () => {
//   console.log("⏰ Monthly Interest Cron Job Started");
//   console.log("Initialized at:", new Date().toISOString());
  
//   // Get current IST time
//   const now = new Date();
//   const istNow = new Date(
//     now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
//   );
  
//   console.log(`🌐 Server UTC: ${now.toISOString()}`);
//   console.log(`🇮🇳 Server IST: ${istNow.toString()}`);
//   console.log(`📅 IST Date: ${istNow.getDate()}/${istNow.getMonth() + 1}/${istNow.getFullYear()}`);
//   console.log(`🕐 IST Time: ${istNow.getHours()}:${istNow.getMinutes()}`);
  
//   // Check if today is last day of month in IST
//   const lastDay = new Date(
//     istNow.getFullYear(),
//     istNow.getMonth() + 1,
//     0
//   ).getDate();
  
//   console.log(`📊 Last day of this month: ${lastDay}`);
//   console.log(`Is today last day? ${istNow.getDate() === lastDay}`);
  
//   // OPTION 1: हर दिन 23:59 IST पर (UTC 18:29)
//   cron.schedule('30 18 * * *', async () => {
//     console.log('\n' + '='.repeat(60));
//     console.log('🕰️ CRON JOB EXECUTED');
//     console.log('UTC:', new Date().toISOString());
    
//     const utcNow = new Date();
//     const currentIST = new Date(
//       utcNow.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
//     );
    
//     console.log(`IST: ${currentIST.toString()}`);
//     console.log(`IST Date: ${currentIST.toLocaleDateString()}`);
//     console.log(`IST Time: ${currentIST.getHours()}:${currentIST.getMinutes()}`);
    
//     // Check if it's actually 23:59-00:00 IST window
//     if (currentIST.getHours() === 23 && currentIST.getMinutes() >= 58) {
//       console.log('✅ It\'s ~23:59 IST');
      
//       // Check if today is last day of month
//       const lastDayOfMonth = new Date(
//         currentIST.getFullYear(),
//         currentIST.getMonth() + 1,
//         0
//       ).getDate();
      
//       if (currentIST.getDate() === lastDayOfMonth) {
//         console.log(`🎯 TODAY IS LAST DAY OF MONTH! (${currentIST.toLocaleDateString()})`);
//         console.log('🏃‍♂️ Running monthly interest calculation...');
        
//         try {
//           await runMonthlyInterestForAll(currentIST);
//           console.log('✅ Monthly interest calculation completed');
//         } catch (error) {
//           console.error('❌ Error:', error.message);
//         }
//       } else {
//         console.log('⏭️ Not last day of month, skipping...');
//       }
//     } else {
//       console.log(`⏰ Not 23:59 IST yet (${currentIST.getHours()}:${currentIST.getMinutes()})`);
//     }
    
//     console.log('='.repeat(60));
//   });
  
//   console.log(`✅ Cron scheduled: Daily at 18:30 UTC (23:59-00:00 IST)`);
  
//   // OPTION 2: Immediate test if today is last day (server start पर)
//   if (istNow.getDate() === lastDay) {
//     console.log('\n🚨 TODAY IS LAST DAY OF MONTH!');
//     console.log('🚀 Running interest calculation immediately...');
    
//     // 5 second delay for server to fully start
//     setTimeout(async () => {
//       try {
//         await runMonthlyInterestForAll(istNow);
//         console.log('✅ Immediate interest calculation completed');
//       } catch (error) {
//         console.error('❌ Immediate calculation failed:', error);
//       }
//     }, 5000);
//   }
// };


// cronJobs/invoiceInterestCron.js
import cron from "node-cron";
import { runMonthlyInterestForAll } from "../controllers/invoiceController.js";

console.log("📌 invoiceInterestCron file loaded");

export const startInterestCron = () => {
  console.log("⏰ MONTH-END INTEREST CRON JOB (23:59 IST)");
  
  // Step 1: Server start time log
  const serverStartTime = new Date();
  const serverStartIST = new Date(
    serverStartTime.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
  );
  
  console.log(`Server started at:`);
  console.log(`  UTC: ${serverStartTime.toISOString()}`);
  console.log(`  IST: ${serverStartIST.toString()}`);
  console.log(`  IST Date: ${serverStartIST.getDate()}/${serverStartIST.getMonth() + 1}/${serverStartIST.getFullYear()}`);
  console.log(`  IST Time: ${serverStartIST.getHours()}:${serverStartIST.getMinutes()}`);
  
  // Step 2: Main Cron - 23:59 IST पर (UTC 18:29)
  // Note: IST 23:59 = UTC 18:29 (winter) or 17:29 (summer)
  // We'll use 18:29 UTC which covers most of the year
  
  cron.schedule('29 18 28-31 * *', async () => {
    console.log('\n' + '='.repeat(70));
    console.log('🌙 MONTH-END CRON TRIGGERED (23:59 IST)');
    console.log('Trigger time UTC:', new Date().toISOString());
    
    const utcNow = new Date();
    const istNow = new Date(
      utcNow.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
    );
    
    console.log(`IST Time: ${istNow.toString()}`);
    console.log(`IST Hour: ${istNow.getHours()}, Minute: ${istNow.getMinutes()}`);
    console.log(`IST Date: ${istNow.getDate()}/${istNow.getMonth() + 1}/${istNow.getFullYear()}`);
    
    // Verify it's actually ~23:59 IST
    if (istNow.getHours() === 23 && istNow.getMinutes() >= 58) {
      console.log('✅ Correct time: ~23:59 IST');
      
      // Check if today is last day of month
      const lastDayOfMonth = new Date(
        istNow.getFullYear(),
        istNow.getMonth() + 1,
        0
      ).getDate();
      
      console.log(`📊 Today's date: ${istNow.getDate()}, Last day of month: ${lastDayOfMonth}`);
      
      if (istNow.getDate() === lastDayOfMonth) {
        console.log(`🎯 TODAY IS LAST DAY OF MONTH! (${istNow.toLocaleDateString()})`);
        console.log('🏃‍♂️ Running monthly interest calculation...');
        
        try {
          await runMonthlyInterestForAll(istNow);
          console.log('✅ Monthly interest calculation completed successfully');
        } catch (error) {
          console.error('❌ Error in interest calculation:', error.message);
        }
      } else {
        console.log('⏭️ Not the last day of month, skipping...');
      }
    } else {
      console.log(`⚠️ Not 23:59 IST (current: ${istNow.getHours()}:${istNow.getMinutes()})`);
      console.log('⏭️ Skipping interest calculation');
    }
    
    console.log('='.repeat(70));
  });
  
  console.log('\n✅ Cron scheduled: 28-31 at 18:29 UTC (23:59 IST)');
  console.log('   This will run at 23:59 IST on last day of every month');
  
  // Step 3: Backup Cron - 23:58 IST (UTC 18:28)
  cron.schedule('28 18 28-31 * *', async () => {
    const utcNow = new Date();
    const istNow = new Date(
      utcNow.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
    );
    
    if (istNow.getHours() === 23 && istNow.getMinutes() === 58) {
      console.log('\n🔄 BACKUP CRON: 23:58 IST');
      
      const lastDay = new Date(
        istNow.getFullYear(),
        istNow.getMonth() + 1,
        0
      ).getDate();
      
      if (istNow.getDate() === lastDay) {
        console.log('🏃‍♂️ Running backup interest calculation...');
        await runMonthlyInterestForAll(istNow);
      }
    }
  });
  
  // Step 4: Emergency check on server start (if server starts on month-end day)
  setTimeout(async () => {
    const now = new Date();
    const istNow = new Date(
      now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
    );
    
    const lastDay = new Date(
      istNow.getFullYear(),
      istNow.getMonth() + 1,
      0
    ).getDate();
    
    if (istNow.getDate() === lastDay) {
      console.log('\n🚨 SERVER STARTED ON MONTH-END DAY!');
      console.log(`IST: ${istNow.getHours()}:${istNow.getMinutes()}`);
      
      // Only run if it's past 18:00 UTC (which means we missed the 23:59 IST cron)
      if (now.getHours() >= 18) {
        console.log('🏃‍♂️ Running missed month-end interest calculation...');
        await runMonthlyInterestForAll(istNow);
      }
    }
  }, 10000); // 10 seconds after server start
};
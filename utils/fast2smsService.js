// // import axios from "axios";

// // export const sendOtpViaFast2SMS = async (phone, otp) => {
// //   try {
// //     const url = "https://www.fast2sms.com/dev/bulkV2";

// //     const payload = {
// //       route: "dlt",
// //       sender_id: process.env.FAST2SMS_SENDER_ID,
// //       message: process.env.FAST2SMS_TEMPLATE_ID,
// //       entity_id: process.env.FAST2SMS_ENTITY_ID,
// //       variables_values: otp,
// //       numbers: phone.replace("+91", ""),
// //       flash: 0,
// //     };

// //     const response = await axios.post(url, payload, {
// //       headers: {
// //         authorization: process.env.FAST2SMS_API_KEY,
// //         "Content-Type": "application/json",
// //       },
// //     });

// //     console.log("SMS Sent:", response.data);

// //     return {
// //       success: true,
// //       data: response.data,
// //     };

// //   } catch (error) {
// //     console.error("Fast2SMS Error:", error.response?.data || error);

// //     return {
// //       success: false,
// //       error: error.response?.data || error.message,
// //     };
// //   }
// // };

// import axios from "axios";

// export const sendOtpViaFast2SMS = async (phone, otp) => {
//   try {
//     const url = "https://www.fast2sms.com/dev/bulkV2";

//     const payload = {
//       route: "dlt",
//       sender_id: process.env.FAST2SMS_SENDER_ID, // BIZBRI
//       message: process.env.FAST2SMS_TEMPLATE_ID, // template id
//       entity_id: process.env.FAST2SMS_ENTITY_ID,
//       variables_values: `${otp}|`, // ⭐ VERY IMPORTANT (pipe required)
//       numbers: phone.replace("+91", ""),
//     };

//     console.log("payload", payload);
//     const response = await axios.post(url, payload, {
//       headers: {
//         authorization: process.env.FAST2SMS_API_KEY.trim(),
//         "Content-Type": "application/json",
//       },
//     });

//     console.log("SMS Sent:", response.data);

//     return {
//       success: true,
//       data: response.data,
//     };
//   } catch (error) {
//     const err = error.response?.data || error.message;

//     console.error("Fast2SMS Error:", err);

//     return {
//       success: false,
//       error: err,
//     };
//   }
// };
import axios from "axios";
export const sendOtpViaFast2SMS = async (phone, otp) => {
  try {
    const payload = {
      route: "dlt",
      sender_id: process.env.FAST2SMS_SENDER_ID, // BIZBRI
      message: process.env.FAST2SMS_TEMPLATE_ID, // 210480 ✅
      variables_values: otp,
      numbers: phone,
    };

    const response = await axios.post(
      "https://www.fast2sms.com/dev/bulkV2",
      payload,
      {
        headers: {
          authorization: process.env.FAST2SMS_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    return { success: true, data: response.data };

  } catch (error) {
    console.error(
      "Fast2SMS Error:",
      error.response?.data || error.message
    );

    return {
      success: false,
      error: error.response?.data || error.message,
    };
  }
};
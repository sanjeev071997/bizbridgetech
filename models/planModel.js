// import mongoose from "mongoose";

// const planSchema = new mongoose.Schema(
//   {
//     name: {
//       type: String,
//       required: true,
//       unique: true,
//     },

//     platforms: {
//       type: [String],
//       enum: ["WEB", "ANDROID", "IOS"],
//       required: true,
//     },

//     title: {
//       type: String,
//       required: false,
//     },

//     // Billing options
//     billingOptions: {
//       monthly: {
//         price: {
//           type: Number,
//           required: true,
//         },
//         discount: {
//           type: Number,
//           default: 0, // Percentage discount for monthly billing
//         },
//       },
//       yearly: {
//         price: {
//           type: Number,
//           required: true,
//         },
//         discount: {
//           type: Number,
//           default: 0, // Percentage discount for yearly billing
//         },
//       },
//     },

//     // Plan validity
//     planValidity: {
//       type: Number, // Number of days the plan is valid for
//       default: 30, // Default to 30 days for monthly
//     },

//     dealerLimit: {
//       type: Number,
//       required: true,
//     },

//     extraDealerPrice: {
//       type: Number,
//       required: true,
//     },

//     setupFee: {
//       type: Number,
//       default: 0,
//     },

//     features: [
//       {
//         type: String,
//       },
//     ],

//     addOns: [
//       {
//         title: String,
//         price: Number,
//         description: String,
//         billingType: {
//           type: String,
//           enum: ["one-time", "monthly", "yearly"],
//           default: "monthly",
//         },
//       },
//     ],

//     isPopular: {
//       type: Boolean,
//       default: false,
//     },

//     isActive: {
//       type: Boolean,
//       default: true,
//     },

//     // For time-limited plans (trial, special offers, etc.)
//     expiryDate: {
//       type: Date,
//       default: null,
//     },

//     // Trial period settings
//     hasTrial: {
//       type: Boolean,
//       default: false,
//     },
//     customPlan:{
//       type: Boolean,
//       default: false,
//     },
//     trialDays: {
//       type: Number,
//       default: 0,
//     },
//   },
//   { timestamps: true }
// );

// // Virtual for formatted expiry date
// planSchema.virtual('formattedExpiryDate').get(function() {
//   if (this.expiryDate) {
//     return this.expiryDate.toISOString().split('T')[0];
//   }
//   return null;
// });

// // Method to check if plan is expired
// planSchema.methods.isExpired = function() {
//   if (this.expiryDate) {
//     return new Date() > this.expiryDate;
//   }
//   return false;
// };

// export default mongoose.model("Plan", planSchema);

import mongoose from "mongoose";

const planSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      unique: true,
    },

    platforms: {
      type: [String],
      enum: ["WEB", "ANDROID", "IOS"],
      required: true,
    },

    title: {
      type: String,
      required: false,
    },

    subTitle: {
      type: String,
      required: false,
    },
    // Billing options
    billingOptions: {
      monthly: {
        price: {
          type: Number,
          required: true,
        },
        discount: {
          type: Number,
          default: 0, // Percentage discount for monthly billing
        },
      },
      yearly: {
        price: {
          type: Number,
          required: false,
        },
        discount: {
          type: Number,
          default: 0, // Percentage discount for yearly billing
        },
      },
    },

    // Plan validity
    planValidity: {
      type: Number, // Number of days the plan is valid for
      default: 30, // Default to 30 days for monthly
    },

    dealerPrice: {
      type: Number,
      required: true,
    },

    setupFee: {
      type: Number,
      default: 0,
    },

    features: [
      {
        type: String,
      },
    ],

    addOns: [
      {
        title: String,
        price: Number,
        description: String,
        billingType: {
          type: String,
          enum: ["one-time", "monthly", "yearly"],
          default: "monthly",
        },
      },
    ],

    isPopular: {
      type: Boolean,
      default: false,
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    // For time-limited plans (trial, special offers, etc.)
    expiryDate: {
      type: Date,
      default: null,
    },

    // Trial period settings
    hasTrial: {
      type: Boolean,
      default: false,
    },
    customPlan:{
      type: Boolean,
      default: false,
    },
    trialDays: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

// Virtual for formatted expiry date
planSchema.virtual('formattedExpiryDate').get(function() {
  if (this.expiryDate) {
    return this.expiryDate.toISOString().split('T')[0];
  }
  return null;
});

// Method to check if plan is expired
planSchema.methods.isExpired = function() {
  if (this.expiryDate) {
    return new Date() > this.expiryDate;
  }
  return false;
};

export default mongoose.model("Plan", planSchema);
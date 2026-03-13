import Plan from "../models/planModel.js";

/**
 * CREATE PLAN
 */
export const createPlan = async (req, res) => {
  try {
    const plan = await Plan.create(req.body);

    res.status(201).json({
      success: true,
      message: "Plan created successfully",
      data: plan,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * GET ALL PLANS
 */
// export const getAllPlans = async (req, res) => {
//   try {
//     const { includeExpired } = req.query;
//     const query = { isActive: true };
    
//     // Optionally include expired plans
//     if (!includeExpired) {
//       query.$or = [
//         { expiryDate: { $gt: new Date() } },
//         { expiryDate: null }
//       ];
//     }

//     const plans = await Plan.find(query).sort({ 'billingOptions.monthly.price': 1 });

//     res.status(200).json({
//       success: true,
//       count: plans.length,
//       data: plans,
//     });
//   } catch (error) {
//     res.status(500).json({
//       success: false,
//       message: error.message,
//     });
//   }
// };

/**
 * GET ALL PLANS - For Super Admin
 */
export const getAllPlans = async (req, res) => {
  try {
    const { includeExpired, includeInactive } = req.query;
    
    // Build query based on user role
    let query = {};
    
    // For Super Admin: show all plans if explicitly requested
    if (req.user?.role === 1) {
      // Super admin can see all plans based on query params
      if (includeInactive === 'true') {
        // Show both active and inactive
        query = {};
      } else {
        // Default: show only active for super admin too
        query.isActive = true;
      }
    } else {
      // For regular users: always show only active plans
      query.isActive = true;
    }
    
    // Handle expiry filtering
    if (!includeExpired || includeExpired !== 'true') {
      query.$or = [
        { expiryDate: { $gt: new Date() } },
        { expiryDate: null }
      ];
    }

    const plans = await Plan.find(query).sort({ 'billingOptions.monthly.price': 1 });

    res.status(200).json({
      success: true,
      count: plans.length,
      data: plans,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * GET ALL PLANS FOR SUPER ADMIN (Alternative endpoint)
 */
export const getAllPlansForSuperAdmin = async (req, res) => {
  try {
    const { includeInactive, includeExpired } = req.query;
    
    let query = {};
    
    // If includeInactive is true, show all plans, otherwise show only active
    if (includeInactive !== 'true') {
      query.isActive = true;
    }
    
    // Handle expiry
    if (includeExpired !== 'true') {
      query.$or = [
        { expiryDate: { $gt: new Date() } },
        { expiryDate: null }
      ];
    }

    const plans = await Plan.find(query).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: plans.length,
      data: plans,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * GET SINGLE PLAN
 */
export const getSinglePlan = async (req, res) => {
  try {
    const plan = await Plan.findById(req.params.id);

    if (!plan) {
      return res.status(404).json({
        success: false,
        message: "Plan not found",
      });
    }

    res.status(200).json({
      success: true,
      data: plan,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * UPDATE PLAN
 */
export const updatePlan = async (req, res) => {
  try {
    const plan = await Plan.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!plan) {
      return res.status(404).json({
        success: false,
        message: "Plan not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Plan updated successfully",
      data: plan,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * SOFT DELETE PLAN
 */
export const deletePlan = async (req, res) => {
  try {
    const plan = await Plan.findByIdAndUpdate(
      req.params.id,
      { isActive: false },
      { new: true }
    );

    if (!plan) {
      return res.status(404).json({
        success: false,
        message: "Plan not found",
      });
    }

    res.status(200).json({
      success: true,
      message: "Plan deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * CALCULATE PRICE (Dealers + Addons + Setup Fee)
 */
export const calculatePlanPrice = async (req, res) => {
  try {
    const { planId, dealersCount, selectedAddOns = [], billingCycle = 'monthly' } = req.body;

    const plan = await Plan.findById(planId);

    if (!plan) {
      return res.status(404).json({
        success: false,
        message: "Plan not found",
      });
    }

    // Check if plan is expired
    if (plan.isExpired()) {
      return res.status(400).json({
        success: false,
        message: "This plan has expired",
      });
    }

    // Get base price based on billing cycle
    let basePrice = billingCycle === 'yearly' 
      ? plan.billingOptions.yearly.price 
      : plan.billingOptions.monthly.price;
    
    let totalAmount = basePrice;

    // Calculate discount
    let discount = billingCycle === 'yearly'
      ? plan.billingOptions.yearly.discount
      : plan.billingOptions.monthly.discount;

    // Extra dealers
    if (dealersCount > plan.dealerLimit) {
      const extraDealers = dealersCount - plan.dealerLimit;
      totalAmount += extraDealers * plan.extraDealerPrice;
    }

    // Add-ons with their billing types
    selectedAddOns.forEach((selectedAddon) => {
      const addon = plan.addOns.find(a => a.title === selectedAddon.title);
      if (addon) {
        // Check if addon billing type matches plan billing cycle
        if (addon.billingType === 'one-time') {
          totalAmount += addon.price;
        } else if (addon.billingType === billingCycle || addon.billingType === 'monthly' && billingCycle === 'yearly') {
          totalAmount += addon.price;
        }
      }
    });

    // Setup fee (one-time)
    totalAmount += plan.setupFee;

    // Apply discount
    if (discount > 0) {
      const discountAmount = (totalAmount * discount) / 100;
      totalAmount -= discountAmount;
    }

    // Calculate savings for yearly vs monthly
    const monthlyPrice = plan.billingOptions.monthly.price;
    const yearlyTotal = monthlyPrice * 12;
    const yearlySavings = yearlyTotal - plan.billingOptions.yearly.price;

    res.status(200).json({
      success: true,
      data: {
        basePrice,
        totalAmount: Math.round(totalAmount * 100) / 100,
        billingCycle,
        discount,
        setupFee: plan.setupFee,
        extraDealers: Math.max(0, dealersCount - plan.dealerLimit),
        extraDealerCost: Math.max(0, dealersCount - plan.dealerLimit) * plan.extraDealerPrice,
        savings: billingCycle === 'yearly' ? yearlySavings : 0,
        planExpiryDate: plan.expiryDate,
        hasTrial: plan.hasTrial,
        trialDays: plan.trialDays,
      },
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * GET ACTIVE PLANS WITH EXPIRY INFO
 */
export const getPlansWithExpiry = async (req, res) => {
  try {
    const plans = await Plan.find({ isActive: true });
    
    const plansWithStatus = plans.map(plan => ({
      ...plan.toObject(),
      status: plan.isExpired() ? 'expired' : 'active',
      daysUntilExpiry: plan.expiryDate 
        ? Math.ceil((plan.expiryDate - new Date()) / (1000 * 60 * 60 * 24))
        : null,
    }));

    res.status(200).json({
      success: true,
      data: plansWithStatus,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

/**
 * RENEW PLAN
 */
export const renewPlan = async (req, res) => {
  try {
    const { id } = req.params;
    const { validityDays } = req.body;

    const plan = await Plan.findById(id);
    
    if (!plan) {
      return res.status(404).json({
        success: false,
        message: "Plan not found",
      });
    }

    // Extend expiry date
    const currentExpiry = plan.expiryDate || new Date();
    const newExpiry = new Date(currentExpiry);
    newExpiry.setDate(newExpiry.getDate() + (validityDays || plan.planValidity));

    plan.expiryDate = newExpiry;
    await plan.save();

    res.status(200).json({
      success: true,
      message: "Plan renewed successfully",
      data: plan,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
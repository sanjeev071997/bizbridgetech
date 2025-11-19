// // Create Token and saving in cookie
// const sendToken = (user, statusCode, res) => {
//   const token = user.getJWTToken();
//   const refreshToken = user.getRefreshToken();

//   // Store refresh token in HTTP-only cookie
//   res.cookie("refreshToken", refreshToken, {
//     httpOnly: true,
//     secure: true, 
//     sameSite: "None",
//     maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
//     path: "/",
//   });

//   res.cookie("token", token, {
//     httpOnly: true,
//     secure: true,
//     sameSite: "None",
//     maxAge: 15 * 60 * 1000, // 15 minute (or you can change to 15 min)
//     path: "/",
//   });

//   res.status(statusCode).json({
//     success: true,
//     user,
//     token,
//     refreshToken,
//   });
// };

// export default sendToken;

// utils/sendToken.js
const sendToken = (user, statusCode, res) => {
  const token = user.getJWTToken();
  const refreshToken = user.getRefreshToken();

  // Store refresh token in HTTP-only cookie
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    // secure: true,
    sameSite: "None",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    path: "/",
  });

  res.cookie("token", token, {
    httpOnly: true,
    // secure: true,
    sameSite: "None",
    maxAge: 15 * 60 * 1000, // 15 min
    path: "/",
  });

  res.status(statusCode).json({
    success: true,
    user,
    token,
    refreshToken,
    expiresIn: 15 * 60, // optional
  });
};

export default sendToken;

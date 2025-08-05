// // Create Token and saving in cookie
// const sendToken = (user, statusCode, res, result ) => {
//     const token = user.getJWTToken();

//     // Options for cookie 
//     const options = {
//         expires: new Date(
//             Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000
//         ),
//         httpOnly: true,
//         secure: true, 
//         sameSite: 'none',
//     };
    
//     res.status(statusCode).cookie("token", token, options).json({
//         success: true,
//         user,
//         token,
//         result
//     });  

// };

// export default sendToken

const sendToken = (user, statusCode, res, result) => {
  const token = user.getJWTToken(); // Short-lived token

  const refreshToken = user.getRefreshToken(); // You will create this function

  const accessTokenOptions = {
    expires: new Date(Date.now() + 15 * 60 * 1000), // 15 min
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  };

  const refreshTokenOptions = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 7 days
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  };

  res
    .status(statusCode)
    .cookie("token", token, accessTokenOptions)
    .cookie("refreshToken", refreshToken, refreshTokenOptions)
    .json({
      success: true,
      user,
      result,
      token,
      refreshToken
    });
};

export default sendToken;

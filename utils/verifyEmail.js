const verifyEmail = (otp, currentYear, userName) => {
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Email Verification OTP</title>
      <style>
          body {
              font-family: Arial, sans-serif;
              background-color: #f7f7f7;
              color: #333;
              margin: 0;
              padding: 0;
          }
          .container {
              max-width: 600px;
              margin: 0 auto;
              background-color: #ffffff;
              border: 1px solid #e0e0e0;
              border-radius: 8px;
              padding: 20px;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          }
          .header {
              background-color: #f4f4f4;
              color: black;
              padding: 20px 0;
              text-align: center;
          }
          .header img {
              max-width: 100px;
              margin-bottom: 10px;
          }
          .content {
              padding: 20px;
              text-align: center;
          }
          .content h1 {
              color: #333;
              font-size: 24px;
          }
          .content p {
              font-size: 16px;
              line-height: 1.5;
              color: #666;
          }
          .otp-box {
              display: inline-block;
              background-color: #f0f0f0;
              border: 2px dashed #2196F3;
              padding: 15px 30px;
              font-size: 24px;
              color: #333;
              letter-spacing: 4px;
              font-weight: bold;
              margin: 20px 0;
              border-radius: 6px;
          }
          .footer {
              text-align: center;
              padding: 20px 0;
              border-top: 1px solid #e0e0e0;
              margin-top: 20px;
              font-size: 12px;
              color: #999;
          }
          .no-reply {
              font-size: 14px;
              color: #999;
              margin-top: 20px;
          }
      </style>
  </head>
  <body>
      <div class="container">
          <div class="header">
              <img src="${process.env.LOGO}" alt="Your Logo">
              <h2>Welcome to Bizbridge!</h2>
          </div>
          <div class="content">
              <h1>Email Verification OTP</h1>
              <p>Hello, <b>${userName}</b></p>
              <p>Thank you for signing up. Please verify your email using the OTP below:</p>
              <div class="otp-box">${otp}</div>
              <p>This OTP is valid for <strong>10 minutes</strong>. Do not share it with anyone.</p>
              <p>If you did not initiate this request, please ignore this email.</p>
              <p>Thanks,<br>The Bizbridge Team</p>
          </div>
          <div class="footer">
              <p>&copy; ${currentYear} Bizbridge. All rights reserved.</p>
              <p>If you have any questions, contact us at 
                <a href="mailto:${process.env.SUPPORT_EMAIL}">${process.env.SUPPORT_EMAIL}</a>
              </p>
              <p class="no-reply">Please do not reply to this email. This inbox is not monitored.</p>
          </div>
      </div>
  </body>
  </html>
  `;
};

export default verifyEmail;


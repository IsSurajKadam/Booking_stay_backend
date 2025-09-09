import { User } from "../models/User.model.js";
import redis from "../utils/redisClient.js";
import { sendEmail } from "../utils/emailService.js";

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

export const sendEmailOTP = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) return res.status(400).json({ message: "Email is required" });

    // 1️⃣ Check if email already registered
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email is already registered" });

    // 2️⃣ Generate OTP
    const otp = generateOTP();

    // 3️⃣ Store OTP in Redis with TTL 5 minutes (300 seconds)
   // await redisClient.set(`otp:${email}`, otp, "EX", 300);
await redis.set(`otp:${email}`, otp, "EX", 300);

await sendEmail({
  to: `"Karpewadi Homestay" <${email}>`, // display name + actual email
  subject: "Karpewadi Homestay | Email Verification OTP",
  html: `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body {
            font-family: 'Arial', sans-serif;
            background-color: #f8f8f8;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background-color: #ffffff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            color: #333333;
          }
          .header {
            text-align: center;
            margin-bottom: 20px;
          }
          .header h1 {
            margin: 0;
            font-size: 28px;
            color: #D65B12;
          }
          h2 {
            color: #5A0000;
            margin-top: 0;
          }
          p {
            font-size: 16px;
            line-height: 1.5;
          }
          .otp {
            font-size: 24px;
            font-weight: bold;
            color: #D65B12;
            margin: 20px 0;
            text-align: center;
          }
          .footer {
            font-size: 12px;
            color: #777777;
            margin-top: 30px;
            text-align: center;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Karpewadi Homestay</h1>
          </div>
          <h2>Email Verification</h2>
          <p>Dear User,</p>
          <p>Your One-Time Password (OTP) for verifying your email is:</p>
          <div class="otp">${otp}</div>
          <p>This OTP is valid for 5 minutes. Please do not share it with anyone.</p>
          <p>If you did not request this verification, please ignore this email.</p>
          <div class="footer">
            Karpewadi Homestay • Trusted Accommodation
          </div>
        </div>
      </body>
    </html>
  `
});


    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to send OTP" });
  }
};

// Verify OTP
export const verifyEmailOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp)
      return res.status(400).json({ message: "Email and OTP are required" });

    const storedOtp = await redis.get(`otp:${email}`);

    if (!storedOtp) {
      return res.status(400).json({ message: "OTP expired or not found" });
    }

    if (storedOtp !== String(otp).trim()) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    await redis.del(`otp:${email}`);

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to verify OTP" });
  }
};

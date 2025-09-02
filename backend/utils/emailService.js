import nodemailer from "nodemailer";
import { config } from "dotenv";
config({
  path:'./config/config.env'
});




const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  service: process.env.SMTP_SERVICE,
  auth: {
    user: process.env.SMTP_MAIL,
    pass: process.env.SMTP_PASSWORD
  }
});

export const sendEmail = async ({ to, subject, text,html }) => {
  await transporter.sendMail({
    from: process.env.SMTP_MAIL,
    to,
    subject,
    text,
    html
  });
};

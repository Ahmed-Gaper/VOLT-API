import nodemailer from 'nodemailer';
import { config } from '../config/config.js';

export const sendEmail = async (options: { email: string; subject: string; message: string }) => {
  // 1) Create a transporter
  const transporter = nodemailer.createTransport({
    host: config.EMAIL_HOST,
    port: parseInt(config.EMAIL_PORT, 10),
    secure: parseInt(config.EMAIL_PORT, 10) === 465,
    auth: {
      user: config.EMAIL_USERNAME,
      pass: config.EMAIL_PASSWORD,
    },
  });

  // 2) Define the email options
  const emailOptions = {
    from: 'Volt <Volt@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  // 3) Actually send the email
  await transporter.sendMail(emailOptions);
};

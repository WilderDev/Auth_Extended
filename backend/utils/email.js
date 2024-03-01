// IMPORTS
const nodemailer = require('nodemailer');

// Nodemailer Config From Ethereal Email
const nodemailerConfig = {
  host: 'smtp.ethereal.email',
  port: 587,
  auth: {
    user: 'jarred.kuhn37@ethereal.email',
    pass: 'RHuE5eRdZyNuXDzEU5',
  },
};

// Send Email Function
const sendEmail = async ({ to, subject, html }) => {
  let testAccount = await nodemailer.createTestAccount(); // Create test nodemailer account

  const transporter = nodemailer.createTransport(nodemailerConfig);

  return transporter.sendMail({
    from: '"Codefi Code Coach" <coderperson@codefi.com>', // sender address
    to,
    subject,
    html,
  });
};

// Send Verification Email Function
const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  // Construct a link to redirect the user to our front end application with their email and their token
  const verifyLink = `${origin}/verify?token=${verificationToken}&email=${email}`;
  const message = `<p>Thanks for creating an account ${name}!</p><a href="${verifyLink}" target="_blank">Verify Here</a>`;

  // Return the sendEmail helper function
  return sendEmail({
    to: email,
    subject: 'Email Confirmation',
    html: message,
  });
};

// Send Reset Password Email Function
const sendResetPassswordEmail = async ({ name, email, token, origin }) => {
  // Construct a link to redirect the user to our front end application with their email and their token
  const resetURL = `${origin}/reset-password?token=${token}&email=${email}`;
  const message = `<p>Please reset password by clicking on the following link :
  <a href="${resetURL}">Reset Password</a></p>`;

  // Return the sendEmail helper function
  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h4>Hello, ${name}</h4>
   ${message}
   `,
  });
};

// EXPORTS
module.exports = {
  sendEmail,
  sendVerificationEmail,
  sendResetPassswordEmail,
};

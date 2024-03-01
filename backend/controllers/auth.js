// IMPORTS
const asyncWrapper = require('./../middleware/async-wrapper.middleware');
const User = require('./../models/user.model');
const Token = require('./../models/token.model');
const crypto = require('crypto');
const {
  sendVerificationEmail,
  sendResetPassswordEmail,
} = require('./../utils/email');
const { attachCookiesToResponse } = require('./../utils/cookie');

// Register Controller
const register = asyncWrapper(async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });

  if (emailAlreadyExists) {
    return res.status(400).json({ msg: 'Email Already In Use' });
  }

  const isFirstAccount = (await User.countDocuments({})) === 0;

  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    name,
    email,
    password,
    role,
    verificationToken,
  });

  // Front end origin
  const origin = 'http://localhost:4200';

  // Utilize sendVerificationEmail help function created
  await sendVerificationEmail({
    name: user.name, // User's name
    email: user.email, // User's email
    verificationToken: user.verificationToken, // User's token
    origin,
  });

  // send verification token back only while testing in postman!!
  res.status(200).json({
    msg: 'Success! Please check your email to veryify your account',
  });
});

// Email Verfication Controller
const verifyEmail = asyncWrapper(async (req, res) => {
  const { verificationToken, email } = req.body; // Get token and email from the request

  const user = await User.findOne({ email }); // Get user by email

  // If no user found or incorrect verification token send 401 error
  if (!user) {
    return res.status(401).json({ msg: 'Verification Failed' });
  }

  if (user.verificationToken !== verificationToken) {
    return res.status(401).json({ msg: 'Verification Failed' });
  }

  // Update user object to verified
  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = '';

  // Save user
  await user.save();

  // Return success response
  res.status(200).json({ msg: 'Email Verified' });
});

// Login Controller
const login = asyncWrapper(async (req, res) => {
  const { email, password } = req.body; // get email and password from request

  if (!email || !password) {
    // check for email and password existance
    return res.status(400).json({ msg: 'Please provide email and password' });
  }

  // Find User
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(401).json({ msg: 'Invalid Credentials' });
  }

  // Use Schema method to compare incoming password to hashed password
  const isPasswordCorrect = await user.comparePassword(password);

  if (!isPasswordCorrect) {
    return res.status(401).json({ msg: 'Invalid Credentials' });
  }

  if (!user.isVerified) {
    return res.status(401).json({ msg: 'Please Verify Your Email' });
  }

  // Create a token user to send to the front end
  const tokenUser = { name: user.name, userId: user._id, role: user.role };

  // Create refresh token
  let refreshToken = '';

  // Check for existing token
  const existingToken = await Token.findOne({ user: user._id });

  if (existingToken) {
    // Extract isValid from existing token
    const { isValid } = existingToken;

    if (!isValid) {
      return res.status(401).json({ msg: 'Invalid Credentials' });
    }
    refreshToken = existingToken.refreshToken;

    // Attach cookies to response
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });

    // Send response
    res.status(200).json({ user: tokenUser });
    return;
  }

  // Collecting information for Token Object
  refreshToken = crypto.randomBytes(40).toString('hex');
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;

  // Constructing token object
  const userToken = {
    refreshToken,
    userAgent,
    ip,
    user: user._id,
  };

  // Creating token
  await Token.create(userToken);

  // Attach cookies to response
  attachCookiesToResponse({ res, user: tokenUser, refreshToken });

  // Send response
  res.status(200).json({ user: tokenUser });
});

// Current User Controller
const me = asyncWrapper(async (req, res) => {
  // Exacting user from request
  const { user } = req;

  res.status(200).json({ user });
});

// Logout Controller
const logout = asyncWrapper(async (req, res) => {
  // Extracting user from request and deleting token
  await Token.findOneAndDelete({ user: req.user.userId });

  // Clearing cookies
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  // Clearing cookies
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.status(200).json({ msg: 'user logged out!' });
});

// Forgot Password Controller
const forgotPassword = asyncWrapper(async (req, res) => {
  // Extract email from request
  const { email } = req.body;

  // Check for email
  if (!email) {
    return res.status(400).json({ msg: 'Please provide email' });
  }

  // Find User
  const user = await User.findOne({ email });

  if (user) {
    // Create password token
    const passwordToken = crypto.randomBytes(70).toString('hex');

    // Send email
    await sendResetPassswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin: 'http://localhost:4200',
    });

    // Ten Minutes
    const tenMinutes = 1000 * 60 * 10;
    // Password Token Expire Date
    const passwordTokenExpireDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = passwordToken;
    user.passwordTokenExpireDate = passwordTokenExpireDate;
    await user.save();
  }

  res.status(200).json({ msg: 'Please Check Your Email!' });
});

// Reset Password Controller
const resetPassword = asyncWrapper(async (req, res) => {
  // Extract email, token, and password from request
  const { email, token, password } = req.body;

  // Check for email, token, and password
  if (!token || !email || !password) {
    return res.status(400).json({ msg: 'Please Provide All Values' });
  }

  // Find User
  const user = await User.findOne({ email });

  if (user) {
    // Current Date
    const currentDate = Date.now();
    if (
      user.passwordToken === token &&
      user.passwordTokenExpireDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpireDate = null;
      await user.save();
    }
  }

  res.status(200).json({ msg: 'Password Reset' });
});

// Exports
module.exports = {
  register,
  login,
  verifyEmail,
  me,
  logout,
  forgotPassword,
  resetPassword,
};

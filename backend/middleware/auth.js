// IMPORTS
const asyncWrapper = require('./async-wrapper.middleware');
const jwt = require('jsonwebtoken');
const Token = require('./../models/token.model');
const attachCookiesToResponse = require('./../utils/cookie');

// Middleware function for authenticating the user
const authenticateUser = asyncWrapper(async (req, res, next) => {
  const { accessToken, refreshToken } = req.signedCookies; // Extracting access token and refresh token from signed cookies

  try {
    if (accessToken) {
      // If access token exists, verify it using the JWT secret
      const { payload } = jwt.verify(accessToken, process.env.JWT_SECRET);

      req.user = payload.user; // Storing the user information from the token in the request object

      return next(); // Proceed to the next middleware or route handler
    }

    if (!refreshToken) {
      return res.status(401).json({ msg: 'Authentication Error' });
    }

    // If access token doesn't exist, verify the refresh token
    const { payload } = jwt.verify(refreshToken, process.env.JWT_SECRET);

    // Find the existing token in the database based on the user ID and refresh token
    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken: payload.refreshToken,
    });

    // If the token doesn't exist or is not valid, return an authentication error
    if (!existingToken || !existingToken.isValid) {
      return res.status(401).json({ msg: 'Authentication Error' });
    }

    // Attach cookies to the response with the user information and the existing refresh token
    attachCookiesToResponse({
      res,
      user: payload.user,
      refreshToken: existingToken.refreshToken,
    });
    // Continue to the next middleware or route handler
    next();
  } catch (error) {
    // Handle any errors that occur during the authentication process
    res.status(500).json({ msg: 'Server Error' });
  }
});

// EXPORTS
module.exports = { authenticateUser };

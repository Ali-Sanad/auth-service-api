import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';

import {createAccessToken, setJWTAccessTokenCookie} from '../utils/helper.js';

export const verifyRole = {
  isAdmin: (req, res, next) => {
    if (req.role === 'admin') {
      next();
    } else {
      res.status(403).json({errors: [{msg: 'Not Authorized'}]});
    }
  },
};
export const authenticateMiddleWare = async (req, res, next) => {
  let accessToken;
  if (req.cookies['access-token']) {
    accessToken = req.cookies['access-token'];
  } else {
    accessToken = req.header('Authorization')?.replace('Bearer ', '');
  }

  const refreshToken = req.cookies['refresh-token'];

  if (!refreshToken && !accessToken) {
    return next();
  }

  try {
    const data = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    req.userId = data.userId;
    req.role = data.role;
    return next();
  } catch {}

  // if the access token is invalid, then we need to check if the refresh token is valid or not
  if (!refreshToken) {
    return next();
  }

  let data;

  try {
    data = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch {
    return next();
  }

  //at this point  we have  a valid refresh token

  //check the user data to create new accessToken  for him
  const user = await User.findById(data?.userId);

  //check if the token has been revoked or not
  //if the token still exists in the valid refresh tokens list in the DB, then it has not been revoked yet and we can continue
  const refreshTokenInDB = await RefreshToken.findOne({token: refreshToken});

  // if token has been invalidated
  if (!user || !refreshTokenInDB) {
    return next();
  }

  //check if the token exist in the user's valid refresh tokens list

  if (!user?.refreshTokens?.includes(refreshTokenInDB?.id)) {
    return next();
  }

  // token has not been invalidated
  //create a new access token
  const token = createAccessToken(user);
  setJWTAccessTokenCookie(token.accessToken, res);
  req.userId = user?.id;
  req.role = user?.role;

  //access token has been refreshed in silent mode

  next();
};

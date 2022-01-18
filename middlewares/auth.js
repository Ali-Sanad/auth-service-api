import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';

export const createRefreshToken = (user) => {
  const refreshToken = jwt.sign(
    {userId: user?.id.toString()},
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: '1d',
    }
  );

  return {refreshToken};
};
export const createAccessToken = (user) => {
  const accessToken = jwt.sign(
    {userId: user?.id.toString()},
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: '15s',
    }
  );

  return {accessToken};
};

export const setJWTCookies = (refreshToken, accessToken, res) => {
  res.cookie('refresh-token', refreshToken, {
    maxAge: 60 * 60 * 24 * 7,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    path: '/',
  });

  res.cookie('access-token', accessToken, {
    maxAge: 60 * 15,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    path: '/',
  });
};

export const authenticateMiddleWare = async (req, res, next) => {
  const refreshToken = req.cookies['refresh-token'];
  // const accessToken = req.cookies['access-token'];
  console.log('req.cookies', req.cookies);
  const accessToken = req.header('Authorization').replace('Bearer ', '');
  if (!refreshToken && !accessToken) {
    return next();
  }

  try {
    const data = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    req.userId = data.userId;
    console.log(data);
    return next();
  } catch {}

  if (!refreshToken) {
    return next();
  }

  let data;

  try {
    data = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch {
    return next();
  }

  const user = await User.findById(data.userId);

  //check if the token has been revoked or not
  //if the token still exists in the valid refresh tokens list in the DB, then it has not been revoked yet and we can continue
  const refreshTokenInDB = await RefreshToken.findOne({token: refreshToken});
  console.log(refreshTokenInDB);

  // if token has been invalidated
  if (!user || !refreshTokenInDB) {
    return next();
  }

  // token has not been invalidated

  const token = createAccessToken(user);
  setJWTCookies(refreshToken, token.accessToken, res);
  req.userId = user?._id.toString();
  next();
};

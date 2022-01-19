import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export const createRefreshToken = (user) => {
  const refreshToken = jwt.sign(
    {userId: user?.id, role: user?.role},
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: '7d',
    }
  );

  return {refreshToken};
};
export const createAccessToken = (user) => {
  const accessToken = jwt.sign(
    {userId: user?.id, role: user?.role},
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: '15m',
    }
  );

  return {accessToken};
};

// 3600 * 24 * 7 * 1000 = 7days in milliseconds
export const setJWTRefreshTokenCookie = (refreshToken, res) => {
  res.cookie('refresh-token', refreshToken, {
    maxAge: 3600 * 24 * 7 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    path: '/',
  });
};
// 15 * 60* 1000 = 15 minutes in milliseconds
export const setJWTAccessTokenCookie = (accessToken, res) => {
  res.cookie('access-token', accessToken, {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    path: '/',
  });
};

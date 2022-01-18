import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export const createRefreshToken = (user) => {
  const refreshToken = jwt.sign(
    {userId: user?.id},
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: '1h',
    }
  );

  return {refreshToken};
};
export const createAccessToken = (user) => {
  const accessToken = jwt.sign(
    {userId: user?.id},
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: '20s',
    }
  );

  return {accessToken};
};

export const setJWTRefreshTokenCookie = (refreshToken, res) => {
  res.cookie('refresh-token', refreshToken, {
    maxAge: 3600 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    path: '/',
  });
};
export const setJWTAccessTokenCookie = (accessToken, res) => {
  res.cookie('access-token', accessToken, {
    maxAge: 20 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true : false,
    path: '/',
  });
};

import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import {check, validationResult} from 'express-validator';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import {authenticateMiddleWare} from '../middlewares/auth.js';
import {
  createAccessToken,
  createRefreshToken,
  setJWTRefreshTokenCookie,
  setJWTAccessTokenCookie,
} from '../utils/helper.js';
dotenv.config();
const router = express.Router();

router.post(
  '/signup',
  [
    check('name', 'Name is required').notEmpty(),
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Password should be 6 characters or more').isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors?.isEmpty()) {
      return res.status(400).json({errors: errors?.array()?.map((e) => e.msg)});
    }

    let {name, email, password} = req.body;

    try {
      //see if user  already exists
      let existingUser = await User.findOne({email});
      if (existingUser) {
        return res.status(400).json({errors: [{msg: 'User  already exists'}]});
      }

      //encrypt password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      //create new user
      //save the user data to database
      await User.create({
        name: name,
        email: email,
        password: hashedPassword,
      });

      res.status(201).send(true);
    } catch (err) {
      console.log(err.message);
      res.status(500).send('Server error');
    }
  }
);

router.post(
  '/login',
  [
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Password should be 6 characters or more').isLength({
      min: 6,
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors?.isEmpty()) {
      return res.status(400).json({errors: errors?.array()?.map((e) => e.msg)});
    }

    let {email, password} = req.body;

    try {
      let user = await User.findOne({email});
      if (!user) {
        return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
      }

      const isPasswordValid = await bcrypt.compare(password, user?.password);
      if (!isPasswordValid) {
        return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
      }
      const {accessToken} = createAccessToken(user);
      const {refreshToken} = createRefreshToken(user);

      //save the refresh token to the database for future use , so that we can revoke the token if needed
      const refreshTokenInDB = await RefreshToken.create({
        token: refreshToken,
        userId: user?.id,
      });

      //save the refresh-token to the  user
      user?.refreshTokens?.push(refreshTokenInDB?._id);
      await user.save();

      setJWTRefreshTokenCookie(refreshToken, res);
      setJWTAccessTokenCookie(accessToken, res);

      res.status(200).json({userId: user?.id, accessToken});
    } catch (err) {
      console.log(err.message);
      res.status(500).send('Server error');
    }
  }
);

router.get('/me', authenticateMiddleWare, async (req, res) => {
  if (!req.userId) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  const user = await User.findById(req.userId);
  if (!user) {
    return res.status(404).json({errors: [{msg: 'User not found'}]});
  }
  try {
    res.status(200).json({
      name: user.name,
      email: user.email,
      userId: user.id,
    });
  } catch (err) {
    console.log(err.message);
    res.status(500).send('Server error');
  }
});

//2nd approatch to generate new access token if the refresh token is valid and not expired.
router.get('/refresh-token', async (req, res) => {
  const refreshToken = req.cookies['refresh-token'];

  if (!refreshToken) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  let data = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

  //at this point  we have  a valid refresh token

  //check the user data to create new accessToken  for him
  const user = await User.findById(data?.userId);

  //check if the token has been revoked or not
  //if the token still exists in the valid refresh tokens list in the DB, then it has not been revoked yet and we can continue
  const refreshTokenInDB = await RefreshToken.findOne({token: refreshToken});

  // if token has been invalidated
  if (!user || !refreshTokenInDB) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  //check if the token exist in the user's valid refresh tokens list
  if (!user?.refreshTokens?.includes(refreshTokenInDB?.id)) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  // token has not been invalidated
  //create a new access token
  const {accessToken} = createAccessToken(user);
  setJWTAccessTokenCookie(accessToken, res);

  res.status(201).json({accessToken});
});

//invalidate Token
router.post('/log-out', async (req, res) => {
  const refreshToken = req.cookies['refresh-token'];
  const accessToken = req.cookies['access-token'];
  console.log('req.cookies', req.cookies);
  if (!refreshToken) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  //check the token is valid or not
  let data;

  try {
    data = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  const user = await User.findById(data?.userId);
  if (!user) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  //remove the refresh token from the database and the user's refresh token list
  const refreshTokenInDB = await RefreshToken.findOne({token: refreshToken});

  try {
    user?.RefreshTokens?.pull(refreshTokenInDB?._id);
    await user.save();
    await RefreshToken.findByIdAndDelete(refreshTokenInDB?._id);
  } catch {
    res.status(401).send(false);
  }

  res.clearCookie('access-token');
  res.clearCookie('refresh-token');

  res.status(200).send(true);
});

export default router;

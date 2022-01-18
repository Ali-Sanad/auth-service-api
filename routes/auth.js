import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import {check, validationResult} from 'express-validator';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import {
  createAccessToken,
  createRefreshToken,
  setJWTCookies,
  authenticateMiddleWare,
} from '../middlewares/auth.js';
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

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]});
      }

      const {accessToken} = createAccessToken(user);
      const {refreshToken} = createRefreshToken(user);

      //save the refresh token to the database for future use , so that we can revoke the token if needed
      await RefreshToken.create({
        token: refreshToken,
      });

      setJWTCookies(refreshToken, accessToken, res);

      res
        .status(200)
        .json({userId: user._id.toString(), accessToken, refreshToken});
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
      userId: user._id.toString(),
    });
  } catch (err) {
    console.log(err.message);
    res.status(500).send('Server error');
  }
});

router.post(
  '/refresh-token',
  [check('token', 'Token is required').notEmpty()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors?.isEmpty()) {
      return res.status(400).json({errors: errors?.array()?.map((e) => e.msg)});
    }

    const refreshToken = req.cookies['refresh-token'];

    // let {token} = req.body;

    try {
      await RefreshToken.findOne({token: refreshToken});
      res.status(201).send(true);
    } catch (err) {
      console.log(err.message);
      res.status(500).send('Server error');
    }
  }
);
/* 
 invalidateTokens: async (_, __, { req }) => {
      if (!req.userId) {
        return false;
      }

      const user = await User.findOne(req.userId);
      if (!user) {
        return false;
      }
      user.count += 1;
      await user.save();

      // res.clearCookie('access-token')

      return true;
    }
*/
export default router;

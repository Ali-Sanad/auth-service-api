import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import {validationResult} from 'express-validator';
import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import {
  createAccessToken,
  createRefreshToken,
  setJWTRefreshTokenCookie,
  setJWTAccessTokenCookie,
} from '../utils/helper.js';
dotenv.config();

const signup = async (req, res) => {
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
};

const login = async (req, res) => {
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

    res.status(200).json({
      accessToken,
      userId: user?.id,
      name: user?.name,
      email: user?.email,
      role: user?.role,
    });
  } catch (err) {
    console.log(err.message);
    res.status(500).send('Server error');
  }
};

const me = async (req, res) => {
  if (!req.userId) {
    return res.status(401).json({errors: [{msg: 'Unauthorized'}]});
  }

  const user = await User.findById(req.userId);
  if (!user) {
    return res.status(404).json({errors: [{msg: 'User not found'}]});
  }
  try {
    res.status(200).json({
      userId: user?.id,
      name: user?.name,
      email: user?.email,
      role: user?.role,
    });
  } catch (err) {
    console.log(err.message);
    res.status(500).send('Server error');
  }
};

const refreshToken = async (req, res) => {
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
};

const logout = async (req, res) => {
  const refreshToken = req.cookies['refresh-token'];
  const accessToken = req.cookies['access-token'];
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

  //remove the refresh-token of this user session from the database and the user's refresh token list.
  //user can be logged in multiple devices at the same time. so we need to invalidate the token of the current device.
  const refreshTokenInDB = await RefreshToken.findOne({token: refreshToken});

  try {
    user?.refreshTokens?.pull(refreshTokenInDB?._id);
    await user.save();
    await RefreshToken.findByIdAndDelete(refreshTokenInDB?._id);
  } catch {
    res.status(401).send(false);
  }

  res.clearCookie('access-token');
  res.clearCookie('refresh-token');

  res.status(200).send(true);
};

const getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select('-password -refreshTokens');
    res.status(200).json(users);
  } catch (err) {
    console.log(err.message);
    res.status(500).send('Server error');
  }
};
export {signup, login, me, refreshToken, logout, getAllUsers};

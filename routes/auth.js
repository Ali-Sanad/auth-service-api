import express from 'express';
import dotenv from 'dotenv';
import {check} from 'express-validator';
import {authenticateMiddleWare} from '../middlewares/auth.js';

import {signup, login, me, refreshToken, logout} from '../controllers/auth.js';
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
  signup
);

router.post(
  '/login',
  [
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Password should be 6 characters or more').isLength({
      min: 6,
    }),
  ],
  login
);

router.get('/me', authenticateMiddleWare, me);

//2nd approatch to generate new access token if the refresh token is valid and not expired.
router.get('/refresh-token', refreshToken);

//invalidate Token
router.post('/log-out', logout);

export default router;

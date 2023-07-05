import jwt from "jsonwebtoken";
import asyncHandler from './asyncHandler';
import User from '../models/userModel.js';

export const protect = asyncHandler(async (req, res, next) => {
    let token;

    // Read the jwt from cookie
    token = req.cookies.jwt;

    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = await User.findById(decoded.userId).select('-password');
            next();
        } catch (err) {
            res.status(401);
            throw new Error('Not authorized, token failed');
        }
    } else {
        res.status(401);
        throw new Error('Not authorized, no token');
    }
})
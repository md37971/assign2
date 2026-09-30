const express = require('express');
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");

const router = express.Router();

const JWT_SECRET = "super_secret_key_123";

//Login and Token Generation
router.post("/login", async function(req,res) {
    try{
        const {username, password} = req.body;

        
        if(!username || !password) { //No username or password was given
            return res.status(400).json({
                success:false,
                message: "No input recieved from username and password"
            });
        }

        const users = await User.findAll();

            const user = users.find(function(u) {
                return u.username === username && u.passwd === password;
            });

        if(!user) {
            return res.status(400).json({
                message: "Invalid username or password"
            })
        }

        const payload = {
            id: user.id,
            username: user.username,
            role: user.role
        }

        const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '3m'});

        res.json({
            message: "Authentication Successful",
            token: token
        })


    }catch(error) {
        res.status(500).json({
            success:false,
            error: error.message
        });
    };
});


//Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    
    //Header format: "Bearer <TOKEN>"
    const token = authHeader && authHeader.split(' ')[1];

    if(!token) {
        return res.status(401).json({
            message: "Access token missing"
        });
    }

    jwt.verify(token, JWT_SECRET, function(err, decodedUser) {
        if(err) {
            return res.status(403).json({
                message: "Invalid or expired token"
            });
        }
        req.user = decodedUser;
        next();
    });
}

module.exports = {
    router,
    authenticateToken
};
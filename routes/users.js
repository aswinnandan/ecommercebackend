const jwt = require('jsonwebtoken');
const { User } = require('../models/user');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

// Middleware for JWT authorization
const auth = (req, res, next) => {
    try {
        let token = req.header('Authorization');
        if (!token) return res.status(401).send('Authorization header is missing');

        const secret = process.env.secret;
        
        token = token
        .substring(7)
        const verified = jwt.verify(token, secret);
        req.user = verified;
        next();
    } catch (error) {
        console.error('JWT Verification Error:', error);
        res.status(400).send('Invalid Token');
    }
};

// Get all users (protected route)
router.get('/', auth, async (req, res) => {
    try {
        var userList
        if (req.user.isAdmin) {
            userList = await User.find().select('-passwordHash');
            
        } else {
            userList = await User.findById(req.user.userId).select('-passwordHash');
            
        }
         res.send(userList);
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// Get a specific user by ID (protected route)
router.get('/:id', auth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-passwordHash');
        if (!user) {
            res.status(500).json({ message: 'The user with the given ID was not found.' });
        } else {
            res.status(200).send(user);
        }
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// Register a new user
router.post('/register', async (req, res) => {
    try {
        let user = new User({
            name: req.body.name,
            email: req.body.email,
            passwordHash: bcrypt.hashSync(req.body.password, 10),
            phone: req.body.phone,
            isAdmin: req.body.isAdmin,
            street: req.body.street,
            apartment: req.body.apartment,
            zip: req.body.zip,
            city: req.body.city,
            country: req.body.country,
        });
        user = await user.save();

        if (!user) {
            return res.status(400).send('The user cannot be created!');
        }
        res.status(201).send({ user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});


// Login route
router.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        const secret = process.env.secret;
        
        if (!user) {
            return res.status(400).send('The user was not found');
        }

        if (user && bcrypt.compareSync(req.body.password, user.passwordHash)) {
            const token = jwt.sign(
                {
                    userId: user.id,
                    isAdmin: user.isAdmin,
                },
                secret,
                { expiresIn: '1d' }
            );

            res.status(200).send({ user: user.email, token: token });
        } else {
            res.status(400).send('Invalid Password');
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update user by ID (protected route)
router.put('/:id', auth, async (req, res) => {
    try {
        const userExist = await User.findById(req.params.id);
        let newPassword;

        if (req.body.password) {
            newPassword = bcrypt.hashSync(req.body.password, 10);
        } else {
            newPassword = userExist.passwordHash;
        }

        const user = await User.findByIdAndUpdate(
            req.params.id,
            {
                name: req.body.name,
                email: req.body.email,
                passwordHash: newPassword,
                phone: req.body.phone,
                isAdmin: req.body.isAdmin,
                street: req.body.street,
                apartment: req.body.apartment,
                zip: req.body.zip,
                city: req.body.city,
                country: req.body.country,
            },
            { new: true }
        );

        if (!user) {
            return res.status(400).send('The user cannot be updated!');
        }

        res.send(user);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete user by ID (protected route)
router.delete('/:id', auth, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (user) {
            return res.status(200).json({ success: true, message: 'The user is deleted!' });
        } else {
            return res.status(404).json({ success: false, message: 'User not found!' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;

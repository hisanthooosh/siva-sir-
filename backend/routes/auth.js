const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// @route   POST api/auth/setup
// @desc    Create the initial Super Admin user (one-time use)
// @access  Public
router.post('/setup', async (req, res) => {
    try {
        // Check if a Super Admin already exists
        let adminUser = await User.findOne({ role: 'Super Admin' });
        if (adminUser) {
            return res.status(400).json({ message: 'Super Admin user already exists.' });
        }

        const newUser = new User({
            name: 'Super Admin',
            email: 'superadmin@test.com',
            password: 'password123', // Will be hashed below
            role: 'Super Admin',
        });

        const salt = await bcrypt.genSalt(10);
        newUser.password = await bcrypt.hash(newUser.password, salt);

        await newUser.save();
        res.status(201).json({ message: 'Super Admin user created successfully. Please login.' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Please provide email and password' });
    }

    try {
        // 1️⃣ Check if user exists
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // 2️⃣ Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const allowedRoles = [
            'Super Admin',
            'HOD',
            'Dean',
            'Registrar',
            'Vice Chancellor',
            'Office Incharge',
            'Clerk',
            'Staff'
        ];

        if (!allowedRoles.includes(user.role)) {
            return res.status(403).json({ message: 'Unauthorized role' });
        }


        // 4️⃣ JWT Payload
        const payload = {
            user: {
                id: user._id,
                name: user.name,
                role: user.role
            }
        };

        // 5️⃣ ✅ SIGN TOKEN AND RETURN IT
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1d' },
            (err, token) => {
                if (err) throw err;

                // 🔥 THIS WAS MISSING
                return res.json({ token });
            }
        );

    } catch (err) {
        console.error('❌ Login error:', err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

module.exports = router;


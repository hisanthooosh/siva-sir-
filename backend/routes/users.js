const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');

/* ======================================================
   ROLE CHECK MIDDLEWARES
====================================================== */

// Super Admin only
const isSuperAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'Super Admin') {
        return res.status(403).json({ message: 'Access denied. Super Admin role required.' });
    }
    next();
};

// Admin or Super Admin
const isAdminOrSuperAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Authentication failed.' });
    }

    if (req.user.role === 'Admin' || req.user.role === 'Super Admin' || req.user.role === 'HOD') {
        return next();
    }

    return res.status(403).json({ message: 'Access denied.' });
};

/* ======================================================
   CREATE USER
   Super Admin → VC / Registrar / Dean / HOD
   HOD → Office Incharge / Clerk / Staff
====================================================== */

router.post('/', authMiddleware, async (req, res) => {
    try {
        const { name, email, password, role, department } = req.body;
        const loggedInUser = req.user;

        if (!name || !email || !password || !role) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        /* ---------- SUPER ADMIN RULES ---------- */
        if (loggedInUser.role === 'Super Admin') {
            const allowedRoles = ['Vice Chancellor', 'Registrar', 'Dean', 'HOD'];

            if (!allowedRoles.includes(role)) {
                return res.status(403).json({
                    message: 'Super Admin can only create VC, Registrar, Dean, or HOD'
                });
            }

            if ((role === 'Dean' || role === 'HOD') && !department) {
                return res.status(400).json({
                    message: 'Department is required for Dean and HOD'
                });
            }
        }

        /* ---------- HOD RULES ---------- */
        if (loggedInUser.role === 'HOD') {
            const allowedRolesForHOD = ['Office Incharge', 'Clerk', 'Staff'];

            if (!allowedRolesForHOD.includes(role)) {
                return res.status(403).json({
                    message: 'HOD can only create Office Incharge, Clerk, or Staff'
                });
            }

            // Force department from HOD
            req.body.department = loggedInUser.department;
        }

        /* ---------- BLOCK OTHERS ---------- */
        if (!['Super Admin', 'HOD'].includes(loggedInUser.role)) {
            return res.status(403).json({ message: 'Access denied' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role,
            department: req.body.department || null,
            managedBy: loggedInUser.id
        });

        await newUser.save();

        res.status(201).json({
            message: 'User created successfully',
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role,
                department: newUser.department
            }
        });

    } catch (err) {
        console.error('❌ Error creating user:', err);
        res.status(500).json({ message: 'Server Error creating user' });
    }
});

/* ======================================================
   GET USERS
   Super Admin → all users
   HOD/Admin → only managed users
====================================================== */

router.get('/', [authMiddleware, isAdminOrSuperAdmin], async (req, res) => {
    try {
        let query = {};

        if (req.user.role === 'HOD' || req.user.role === 'Admin') {
            query = { managedBy: req.user.id };
        }

        const users = await User.find(query)
            .select('-password')
            .populate('managedBy', 'name email')
            .sort({ role: 1, name: 1 });

        res.json(users);
    } catch (err) {
        console.error('❌ Error fetching users:', err);
        res.status(500).json({ message: 'Server Error fetching users' });
    }
});

/* ======================================================
   DELETE USER
====================================================== */

router.delete('/:id', [authMiddleware, isAdminOrSuperAdmin], async (req, res) => {
    try {
        const userToDelete = await User.findById(req.params.id);
        if (!userToDelete) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (userToDelete.id === req.user.id) {
            return res.status(400).json({ message: 'You cannot delete your own account.' });
        }

        let canDelete = false;

        if (req.user.role === 'Super Admin') {
            canDelete = true;
        } else if (
            (req.user.role === 'HOD' || req.user.role === 'Admin') &&
            userToDelete.managedBy?.toString() === req.user.id
        ) {
            canDelete = true;
        }

        if (!canDelete) {
            return res.status(403).json({ message: 'Permission denied' });
        }

        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'User deleted successfully' });

    } catch (err) {
        console.error('❌ Error deleting user:', err);
        res.status(500).json({ message: 'Server Error deleting user' });
    }
});

/* ======================================================
   SUPER ADMIN – ALL USERS OVERVIEW
====================================================== */

router.get('/all', [authMiddleware, isSuperAdmin], async (req, res) => {
    try {
        const allUsers = await User.find({})
            .select('-password')
            .populate('managedBy', 'name email')
            .sort({ role: 1, name: 1 });

        res.json(allUsers);
    } catch (err) {
        console.error('❌ Error fetching all users:', err);
        res.status(500).json({ message: 'Server Error fetching all users' });
    }
});

module.exports = router;

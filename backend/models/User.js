const mongoose = require('mongoose');
const { Schema } = mongoose; // <<< ADD THIS LINE

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true, // Each email must be unique
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: [
            'Super Admin',
            'Dean',
            'HOD',
            'Office Incharge',
            'Clerk',
            'Staff',
            'Registrar',
            'Vice Chancellor',
            'Circular Creator',
            'Circular Approver',
            'Circular Viewer'
        ],
        required: true
    }
    ,


    department: {
        type: String,
        // This is not required for all users, but useful for Viewers
        required: false,
    },
    // This will automatically add 'createdAt' and 'updatedAt' fields
    department: {
        type: String,
        required: false,
    }, // <--- After this comma and brace

    // Add this new field definition:
    managedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: false // Not required for Super Admin or CAs
    },
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);


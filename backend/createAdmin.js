const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const User = require('./models/User'); 

dotenv.config();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB Connected...');
  } catch (err) {
    console.error('Database connection error:', err.message);
    process.exit(1);
  }
};

const createSuperAdmin = async () => {
  await connectDB();

  try {
    // 1. Check if user already exists
    const adminEmail = "superadmin@college.edu"; 
    let user = await User.findOne({ email: adminEmail });

    if (user) {
      console.log('Super Admin user already exists');
      process.exit();
    }

    // 2. Encrypt Password
    const passwordPlain = "Super@123"; 
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(passwordPlain, salt);

    // 3. Create User with "Super Admin" role
    user = new User({
      name: "Main Super Admin",
      email: adminEmail,
      password: hashedPassword,
      role: "Super Admin", // <--- MUST MATCH ENUM EXACTLY
      department: "Management"
    });

    await user.save();
    console.log('✅ Super Admin Created Successfully!');
    console.log(`Email: ${adminEmail}`);
    console.log(`Password: ${passwordPlain}`);
    
    process.exit();
  } catch (err) {
    console.error("Error creating admin:", err.message);
    process.exit(1);
  }
};

createSuperAdmin();
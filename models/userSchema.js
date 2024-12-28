import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const userSchema = new mongoose.Schema({
  userName: {
    type: String,
    required: [true, "Username is required"],
    minLength: [3, "Username must contain at least 3 characters"],
    maxLength: [40, "Username cannot exceed 40 characters"],
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    select: false,
    minLength: [8, "Password must contain at least 8 characters"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    match: [/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/, "Please enter a valid email"]
  },
  address: String,
  phone: {
    type: String,
    required: [true, "Phone number is required"],
    match: [/^[6-9]\d{9}$/, "Please enter a valid 10-digit Indian mobile number"],
  },
  profileImage: {
    public_id: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
  },
  paymentMethods: {
    bankTransfer: {
      bankAccountNumber: String,
      bankAccountName: String,
      bankName: String,
      ifscCode: {
        type: String,
        match: [/^[A-Z]{4}0[A-Z0-9]{6}$/, "Invalid IFSC code"]
      }
    },
    upi: {
      upiId: String
    },
    paypal: {
      paypalEmail: String
    },
  },
  role: {
    type: String,
    required: true,
    enum: ["Auctioneer", "Bidder", "Super Admin"],
  },
  kycDetails: {
    aadharNumber: String,
    panNumber: String,
    isVerified: {
      type: Boolean,
      default: false
    }
  },
  unpaidCommission: {
    type: Number,
    default: 0,
  },
  auctionsWon: {
    type: Number,
    default: 0,
  },
  moneySpent: {
    type: Number,
    default: 0,
  }
}, {
  timestamps: true
});

userSchema.pre("save", async function(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
});

userSchema.methods.comparePassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.generateJsonWebToken = function() {
  return jwt.sign(
    { id: this._id }, 
    process.env.JWT_SECRET_KEY, 
    { expiresIn: process.env.JWT_EXPIRE }
  );
};

export const User = mongoose.model("User", userSchema);
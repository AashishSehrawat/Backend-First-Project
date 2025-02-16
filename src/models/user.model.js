import mongoose from "mongoose";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';


const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        unique: true,
        lowercase: true,
        trim: true,
        index: true,
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
    },
    fullname: {
        type: String,
        required: [true, 'Fullname is required'],
        trim: true,
        index: true,
    },
    avatar: {
        type: String,
        required: [true, 'Avatar is required'],
    },
    coverImage: {
        type: String,
    },
    watchHistory: [
        {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Video",
        },
    ],
    password: {
        type: String,
        required: [true, 'Password is required'],
    },
    refershToken: {
        type: String,
    }
} , { timestamps: true })


// encrypt the password
userSchema.pre("save" , async function(next) {
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10);
    next();
})

// check if password is correct is not
userSchema.methods.isPasswordCorrect = async function(password) {
    return await bcrypt.compare(password, this.password);
}


// generate jwt token
userSchema.methods.generateAccessToken = function() {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullname: this.fullname,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        },
    )
}



// generate refersh token
userSchema.methods.generateRefreshToken = function() {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOEKN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOEKN_EXPIRY,
        }
    )
}


export const User = mongoose.model("User" , userSchema);
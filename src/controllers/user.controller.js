import { asyncHandler } from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import {ApiResponse} from '../utils/ApiResponse.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import jwt from 'jsonwebtoken';


const generateAccessTokenAndRefreshToken = async (userID) => {
    try {
        const user = await User.findById(userID);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        // add refersh token in database
        user.refreshToken = refreshToken;
        await user.save( { validateBeforeSave: false } )

        return {accessToken, refreshToken};

    } catch (error) {
        throw new ApiError(500, "Somrthing went wrong while generating tokens");
    }
}

const registerUser = asyncHandler( async (req, res) => {
    // get user details from frontend
    // validation on details getting - non-empty
    // if user is already is created: username and email
    // check for images, check for avtar
    // upload them to cloudinary, avtar
    // create user object = create entry in database
    // remove password and refersh token form response
    // check user is created
    // return response

    const {fullname, username, email, password} = req.body;
    console.log(req.body);
    console.log("Email", email);


    
    if (
        [fullname, username, email, password].some((field) => field?.trim === "")
    ) {
        throw new ApiError(400, "All fields are required");
    }



    const existedUser = await User.findOne({
        $or: [ { username } , { email } ]
    })
    if(existedUser) {
        throw new ApiError(409, "User with email or username already exist")
    }


    const avatarLocalpath = req.files?.avatar[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalpath) {
        throw new ApiError(400, "Avatar is required");
    }
   

    const avatar = await uploadOnCloudinary(avatarLocalpath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if(!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }


    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(),
    })


    const createdUser = await User.findById(user._id).select(
        "-password -refershToken"
    )


    if(!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user");
    }


    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registerd succesfully")
    )

} )



const loginUser = asyncHandler( async (req, res) => {
    // req body => data
    // username or eamil 
    // find the user
    // check the password
    // access and refersh token
    // send cookie

    const {email, username, password} = req.body;

    if( !username && !email ){
        throw new ApiError(400, "Username or email is required");
    }

    const user = await User.findOne({
        $or: [ {username} , {email} ]
    })

    if(!user) {
        throw new ApiError(404, "User doesn't exist");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if(!isPasswordValid) {
        throw new ApiError(400, "Password or email is wrong");
    }

    const { accessToken, refreshToken } = await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");  

    // cookies
    const options = {
        httpOnly: true,
        secure: true
    }

    return res.status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User logges In"
            )
        )
})

const logoutUser = asyncHandler( async (req, res) => {
    // remove refershtokem from database
    // clear cookie

    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined,
            }
        },
        {
            new: true,
        }
    )


    const options = {
        httpOnly: true,
        secure: true,
    }

    return res.status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiError(200, {}, "User logged Out"));
})


const refreshAccessToken = asyncHandler( async (req, res) => {
    // get the refresh token from user
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if(!incomingRefreshToken) {
        throw new ApiError(401, "Unauthorized access");
    }

    // check if user's refresh token is same as database refresh token
    try {
        const decodedRefershToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedRefershToken?._id);
    
        if( !user ){
            throw new ApiError(404, "Invalid refresh token by user");
        }
    
        if(incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {newAccessToken, newRefreshToken } = await generateAccessTokenAndRefreshToken(user._id)
    
        return res.status(200)
            .cookie("accessToken", newAccessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {
                        accessToken: newAccessToken,
                        refreshToken: newRefreshToken
                    },
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

export { 
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
}


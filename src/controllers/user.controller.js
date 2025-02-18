import { asyncHandler } from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js';
import {ApiResponse} from '../utils/ApiResponse.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';


const generateAccessTokenAndRefreshToken = async (userID) => {
    try {
        const user = await User.findById(userID);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        
        // add refersh token in database
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false })

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
        const decodedRefreshToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedRefreshToken?._id);
    
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


const changeCurrentPassword = asyncHandler( async (req, res) => {
    const {oldPassword, newPassword} = req.body;

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if(!isPasswordCorrect) {
        throw new ApiError(400, "Invalid Password");
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false});

    return res.status(200)
        .json(
            new ApiResponse(200, {}, "Password changes successfully")
        )
})


const getCurrentUser = asyncHandler( async (req, res) => {
    return res.status(200)
        .json(
            new ApiResponse(200, req.user, "User successfully feched")
            )
})


const updateAccountDetails = asyncHandler( async (req, res) => {
    const {fullname, email} = req.body;

    if (!fullname || !email) {
        throw new ApiError(400, "All feilds are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullname: fullname,
                email: email
            }
        },
        {
            new: true,
        }
    ).select("-password")

    return res.status(200)
        .json( new ApiResponse(
            200,
            user,
            "Fullname or email is updated"
        ))
})


const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar is not avaliable")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if(!avatar.url) {
        throw new ApiError(400, "Avatar is not upladed on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {
            new: true,
        }
    ).select("-password")

    return res.status(200)
        .json(new ApiResponse(
            200,
            user,
            "Avatar updated successfully"
        ))
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if(!coverImageLocalPath) {
        throw new ApiError(400, "Invalid Cover image path")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if(!coverImage.url) {
        throw new ApiError(400, "Coverimage doesn't upload on cloudinary")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url,
            }
        },
        {
            new: true,

        }
    ).select("-password")


    return res.status(200)
        .json(
            new ApiResponse(
                200,
                user,
                "Cover Image update succesfully"
            ))

})


const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { username } = req.params;

    if(!username?.trim()) {
        throw new ApiError(404, "Channel name missing");
    }

    const channel = await User.aggregate([
        // finding the user 
        {
            $match: {
                username: username?.toLowerCase(),
            }
        },
        // join the collections
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        // join the collection
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        // adding fields to user
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false,
                    }
                }
            }
        },
        // sending data to frontend
        {
            $project:{
                username: 1,
                fullname: 1,
                coverImage: 1,
                avatar: 1,
                email: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
            }
        }

    ])

    if(!channel?.length) {
        throw new ApiError(404, "Channel doesn't exist")
    }

    return res.status(200)
        .json(
            new ApiResponse(200, channel[0], "User channeled feached")
        )
})


const getWatchHistory = asyncHandler( async (req, res) => {
    const user = await User.aggregate([
        {
           $match: {
            _id: new mongoose.Types.ObjectId(req.user._id)
           } 
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullname: 1,
                                        avaliable: 1,
                                        username: 1,
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner",
                            }
                        }
                    },
                ]
            }
        }
    ])

    return res.status(200)
        .json(
            new ApiResponse(200, user[0].watchHistory, "Watch history is feched")
        )
})


export {  
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory,
}


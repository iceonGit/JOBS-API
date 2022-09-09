const User = require("../models/User");
const jwt  = require("jsonwebtoken");
const {UnauthenticatedError} = require("../errors");



const auth = (req,res,next)=>{
  const authHeader = req.headers.authorization;
  if(!authHeader || !authHeader.startsWith("Bearer")){
    throw new UnauthenticatedError("No token provided");
  }

  const token  = authHeader.split(" ")[1];
  try{
    const payload = jwt.verify(token,process.env.JWT_SECRET);
    req.user = {userId:payload.userId,name:payload.name};

    next();
  }catch(err){
    throw new UnauthenticatedError("Not authorized to access this route");
  }
}


module.exports = auth

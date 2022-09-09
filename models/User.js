const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  name:{
    type:String,
    required:[true,"Think you can get away without giving your name,kind stranger?"],
    minlength:3,
    maxlength:50
  },
  email:{
    type:String,
    required:[true,"The email field isn't gonna be filled with tumbleweeds"],
    match:[
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      "Temp mails and spelling errors aren't gonna fly here..."
    ],
    unique:true,
  },
  password:{
    type:String,
    required:[true,"Can't get in without a password now , can you ?"],
    minlength:6,
  }

})

userSchema.pre("save",async function(next){

  const salt  = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password,salt);
  next();
})

userSchema.methods.createJWT = function(){
  return jwt.sign({userId:this._id,name:this.name},process.env.JWT_SECRET,{expiresIn:process.env.JWT_LIFETIME});
}

userSchema.methods.comparePassword = async function(candidatePassword){
  const isMatch = await bcrypt.compare(candidatePassword,this.password);
  return isMatch
}

module.exports = mongoose.model("User",userSchema);

import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
    {
        email:{
            type:String,
            required:true,
            unique:true,
        },
        password:{
            type:String,
            required:true,
        }
    },
    { timestamps: true }
)


userSchema.pre("save",async function(){
    if(!this.isModified("password")){
        return;
    }
    this.password = await bcrypt.hash(this.password,10);
})

const User = mongoose.model("User",userSchema);
export default User;
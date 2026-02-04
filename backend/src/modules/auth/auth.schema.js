import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema(
    {
        email:{
            type:String,
            required:true,
            unique:true,
            lowercase:true,
            index:true
        },
        password:{
            type:String,
            required:true,
            select:false
        },
        role:{
            type:String,
            enum:['user','admin'],
            default:'user'
        },
        isEmailVerified:{
            type:Boolean,
            default:false
        }
    },
    {
        timestamps:true
    }
)

userSchema.pre("save",async function(next){
    if(!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password,12)
    next()
})

userSchema.methods.comparePassword = async function(candidatePassword){
    return await bcrypt.compare(candidatePassword,this.password);
}

const User = mongoose.model("User",userSchema);

export default User;